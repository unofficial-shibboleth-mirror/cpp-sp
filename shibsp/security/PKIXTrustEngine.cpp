/*
 *  Copyright 2001-2007 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * PKIXTrustEngine.cpp
 * 
 * Shibboleth-specific PKIX-validation TrustEngine
 */

#include "internal.h"
#include "metadata/MetadataExt.h"
#include "security/PKIXTrustEngine.h"

#include <saml/saml2/metadata/Metadata.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/security/AbstractPKIXTrustEngine.h>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace xmlsignature;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    /**
     * Adapter between shibmd:KeyAuthority extension and the PKIXValidationInfoIterator interface. 
     */
    class SHIBSP_API MetadataPKIXIterator : public AbstractPKIXTrustEngine::PKIXValidationInfoIterator
    {
        const XMLObject* m_obj;
        const Extensions* m_extBlock;
        const KeyAuthority* m_current;
        vector<XMLObject*>::const_iterator m_iter;
        
        bool m_certsOwned;
        vector<XSECCryptoX509*> m_certs;
        vector<XSECCryptoX509CRL*> m_crls;
        
    public:
        MetadataPKIXIterator(const RoleDescriptor& role, const KeyResolver& keyResolver)
            : PKIXValidationInfoIterator(keyResolver), m_obj(role.getParent()), m_extBlock(NULL), m_current(NULL), m_certsOwned(false) {
        }

        virtual ~MetadataPKIXIterator() {
            clear();
        }

        bool next();

        int getVerificationDepth() const {
            pair<bool,int> vd = m_current->getVerifyDepth();
            return vd.first ? vd.second : 1;
        }
        
        const vector<XSECCryptoX509*>& getTrustAnchors() const {
            return m_certs;
        }

        const vector<XSECCryptoX509CRL*>& getCRLs() const {
            return m_crls;
        }
    
    private:
        void populate();

        void clear() {
            if (m_certsOwned)
                for_each(m_certs.begin(), m_certs.end(), xmltooling::cleanup<XSECCryptoX509>());
            m_certs.clear();
            for_each(m_crls.begin(), m_crls.end(), xmltooling::cleanup<XSECCryptoX509CRL>());
            m_crls.clear();
        }
    };

    class SHIBSP_DLLLOCAL PKIXTrustEngine : public AbstractPKIXTrustEngine
    {
    public:
        PKIXTrustEngine(const DOMElement* e=NULL) : AbstractPKIXTrustEngine(e) {}
        virtual ~PKIXTrustEngine() {}
        
        AbstractPKIXTrustEngine::PKIXValidationInfoIterator* getPKIXValidationInfoIterator(
            const KeyInfoSource& pkixSource, const KeyResolver& keyResolver
            ) const;
    };
    
    SHIBSP_DLLLOCAL PluginManager<TrustEngine,const DOMElement*>::Factory PKIXTrustEngineFactory;

    TrustEngine* SHIBSP_DLLLOCAL PKIXTrustEngineFactory(const DOMElement* const & e)
    {
        return new PKIXTrustEngine(e);
    }
};

void shibsp::registerPKIXTrustEngine()
{
    XMLToolingConfig::getConfig().TrustEngineManager.registerFactory(SHIBBOLETH_PKIX_TRUSTENGINE, PKIXTrustEngineFactory);
}

AbstractPKIXTrustEngine::PKIXValidationInfoIterator* PKIXTrustEngine::getPKIXValidationInfoIterator(
    const KeyInfoSource& pkixSource, const KeyResolver& keyResolver
    ) const
{
    return new MetadataPKIXIterator(dynamic_cast<const RoleDescriptor&>(pkixSource),keyResolver);
}

bool MetadataPKIXIterator::next()
{
    // If we had an active block, look for another in the same block.
    if (m_extBlock) {
        // Keep going until we hit the end of the block.
        vector<XMLObject*>::const_iterator end = m_extBlock->getUnknownXMLObjects().end();
        while (m_iter != end) {
            // If we hit a KeyAuthority, remember it and signal.
            if (m_current=dynamic_cast<KeyAuthority*>(*m_iter++)) {
                populate();
                return true;
            }
        }
        
        // If we get here, we hit the end of this Extensions block.
        // Climb a level, if possible.
        m_obj = m_obj->getParent();
        m_current = NULL;
        m_extBlock = NULL;
    }

    // If we get here, we try and find an Extensions block.
    while (m_obj) {
        const EntityDescriptor* entity = dynamic_cast<const EntityDescriptor*>(m_obj);
        if (entity) {
            m_extBlock = entity->getExtensions();
        }
        else {
            const EntitiesDescriptor* entities = dynamic_cast<const EntitiesDescriptor*>(m_obj);
            if (entities) {
                m_extBlock = entities->getExtensions();
            }
        }
        
        if (m_extBlock) {
            m_iter = m_extBlock->getUnknownXMLObjects().begin();
            return next();
        }
        
        // Jump a level and try again.
        m_obj = m_obj->getParent();
    }

    return false;
}

void MetadataPKIXIterator::populate()
{
    // Dump anything old.
    clear();

    // We have to aggregate the resolution results.
    KeyResolver::ResolvedCertificates certs;
    XSECCryptoX509CRL* crl;
    const vector<KeyInfo*>& keyInfos = m_current->getKeyInfos();
    for (vector<KeyInfo*>::const_iterator k = keyInfos.begin(); k!=keyInfos.end(); ++k) {
        vector<XSECCryptoX509*>::size_type count = m_keyResolver.resolveCertificates(*k,certs); 
        if (count > 0) {
            // Transfer certificates out of wrapper. 
            bool own = certs.release(m_certs);
            if (!m_certs.empty() && own != m_certsOwned) {
                // Ugh. We have a mashup of "owned" and "unowned".
                // The ones we just added need to be removed and perhaps freed.
                do {
                    if (own)
                        delete m_certs.back();
                    m_certs.pop_back();
                } while (--count > 0);
            }
            m_certsOwned = own;
        }

        crl = m_keyResolver.resolveCRL(*k);
        if (crl)
            m_crls.push_back(crl);
    }
}

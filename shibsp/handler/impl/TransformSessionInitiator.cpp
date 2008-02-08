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
 * TransformSessionInitiator.cpp
 * 
 * Support for mapping input into an entityID using a transform.
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "handler/RemotedHandler.h"
#include "handler/SessionInitiator.h"
#include "util/SPConstants.h"

#ifndef SHIBSP_LITE
# include <saml/saml2/metadata/Metadata.h>
#endif
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/signature/KeyInfo.h>
#include <xmltooling/util/URLEncoder.h>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL TransformSINodeFilter : public DOMNodeFilter
    {
    public:
        short acceptNode(const DOMNode* node) const {
            if (XMLString::equals(node->getLocalName(), xmlsignature::Transform::LOCAL_NAME))
                return FILTER_REJECT;
            return FILTER_ACCEPT;
        }
    };

    static SHIBSP_DLLLOCAL TransformSINodeFilter g_TSINFilter;

    class SHIBSP_DLLLOCAL TransformSessionInitiator : public SessionInitiator, public AbstractHandler, public RemotedHandler
    {
    public:
        TransformSessionInitiator(const DOMElement* e, const char* appId)
                : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionInitiator.Transform"), &g_TSINFilter), m_appId(appId) {
            // If Location isn't set, defer address registration until the setParent call.
            pair<bool,const char*> loc = getString("Location");
            if (loc.first) {
                string address = m_appId + loc.second + "::run::TransformSI";
                setAddress(address.c_str());
            }

#ifndef SHIBSP_LITE
            if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
                e = XMLHelper::getFirstChildElement(e, xmlsignature::Transform::LOCAL_NAME);
                while (e) {
                    if (e->hasChildNodes()) {
                        auto_ptr_char temp(e->getFirstChild()->getNodeValue());
                        m_transforms.push_back(temp.get());
                    }
                    e = XMLHelper::getNextSiblingElement(e, xmlsignature::Transform::LOCAL_NAME);
                }
            }
#endif
        }

        virtual ~TransformSessionInitiator() {}
        
        void setParent(const PropertySet* parent);
        void receive(DDF& in, ostream& out);
        pair<bool,long> run(SPRequest& request, string& entityID, bool isHandler=true) const;

    private:
        void doRequest(const Application& application, string& entityID) const;
        string m_appId;
#ifndef SHIBSP_LITE
        vector<string> m_transforms;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    SessionInitiator* SHIBSP_DLLLOCAL TransformSessionInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new TransformSessionInitiator(p.first, p.second);
    }

};

void TransformSessionInitiator::setParent(const PropertySet* parent)
{
    DOMPropertySet::setParent(parent);
    pair<bool,const char*> loc = getString("Location");
    if (loc.first) {
        string address = m_appId + loc.second + "::run::TransformSI";
        setAddress(address.c_str());
    }
    else {
        m_log.warn("no Location property in Transform SessionInitiator (or parent), can't register as remoted handler");
    }
}

pair<bool,long> TransformSessionInitiator::run(SPRequest& request, string& entityID, bool isHandler) const
{
    // We have to have a candidate name to function.
    if (entityID.empty())
        return make_pair(false,0L);

    string target;
    const Application& app=request.getApplication();

    m_log.debug("attempting to transform input (%s) into a valid entityID", entityID.c_str());

    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess))
        doRequest(app, entityID);
    else {
        // Remote the call.
        DDF out,in = DDF(m_address.c_str()).structure();
        DDFJanitor jin(in), jout(out);
        in.addmember("application_id").string(app.getId());
        in.addmember("entity_id").string(entityID.c_str());
    
        // Remote the processing.
        out = request.getServiceProvider().getListenerService()->send(in);
        if (out.isstring())
            entityID = out.string();
    }
    
    return make_pair(false,0L);
}

void TransformSessionInitiator::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid=in["application_id"].string();
    const Application* app=aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : NULL;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) to generate AuthnRequest", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for new session, deleted?");
    }

    const char* entityID = in["entity_id"].string();
    if (!entityID)
        throw ConfigurationException("No entityID parameter supplied to remoted SessionInitiator.");

    string copy(entityID);
    doRequest(*app, copy);
    DDF ret = DDF(NULL).string(copy.c_str());
    DDFJanitor jout(ret);
    out << ret;
}

void TransformSessionInitiator::doRequest(const Application& application, string& entityID) const
{
#ifndef SHIBSP_LITE
    MetadataProvider* m=application.getMetadataProvider();
    Locker locker(m);

    // First check the original value, it might be valid already.
    MetadataProvider::Criteria mc(entityID.c_str(), &IDPSSODescriptor::ELEMENT_QNAME);
    pair<const EntityDescriptor*,const RoleDescriptor*> entity = m->getEntityDescriptor(mc);
    if (entity.first)
        return;

    // Guess not, try each transform.
    string transform;
    for (vector<string>::const_iterator t = m_transforms.begin(); t != m_transforms.end(); ++t) {
        transform = *t;
        string::size_type pos = transform.find("$entityID");
        if (pos == string::npos)
            continue;
        transform.replace(pos, 9, entityID);
        m_log.debug("attempting lookup with entityID (%s)", transform.c_str());
    
        mc.entityID_ascii = transform.c_str();
        entity = m->getEntityDescriptor(mc);
        if (entity.first) {
            m_log.info("transformed entityID from (%s) to (%s)", entityID.c_str(), transform.c_str());
            entityID = transform;
            return;
        }
    }

    m_log.warn("unable to find a valid entityID based on the supplied input");
#endif
}

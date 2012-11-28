/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * XMLServiceProvider.cpp
 *
 * XML-based SP configuration and mgmt.
 */

#include "internal.h"
#include "exceptions.h"
#include "version.h"
#include "AccessControl.h"
#include "Application.h"
#include "RequestMapper.h"
#include "ServiceProvider.h"
#include "SessionCache.h"
#include "SPConfig.h"
#include "SPRequest.h"
#include "binding/ProtocolProvider.h"
#include "handler/LogoutInitiator.h"
#include "handler/SessionInitiator.h"
#include "remoting/ListenerService.h"
#include "util/DOMPropertySet.h"
#include "util/SPConstants.h"

#if defined(XMLTOOLING_LOG4SHIB)
# include <log4shib/PropertyConfigurator.hh>
#elif defined(XMLTOOLING_LOG4CPP)
# include <log4cpp/PropertyConfigurator.hh>
#else
# error "Supported logging library not available."
#endif
#include <algorithm>
#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/tuple/tuple.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xercesc/util/XMLStringTokenizer.hpp>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/version.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReloadableXMLFile.h>
#include <xmltooling/util/TemplateEngine.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>

#ifndef SHIBSP_LITE
# include "attribute/filtering/AttributeFilter.h"
# include "attribute/resolver/AttributeExtractor.h"
# include "attribute/resolver/AttributeResolver.h"
# include "security/PKIXTrustEngine.h"
# include "security/SecurityPolicyProvider.h"
# include <saml/exceptions.h>
# include <saml/version.h>
# include <saml/SAMLConfig.h>
# include <saml/binding/ArtifactMap.h>
# include <saml/binding/SAMLArtifact.h>
# include <saml/saml1/core/Assertions.h>
# include <saml/saml2/core/Assertions.h>
# include <saml/saml2/binding/SAML2ArtifactType0004.h>
# include <saml/saml2/metadata/EntityMatcher.h>
# include <saml/saml2/metadata/Metadata.h>
# include <saml/saml2/metadata/MetadataProvider.h>
# include <saml/util/SAMLConstants.h>
# include <xmltooling/security/ChainingTrustEngine.h>
# include <xmltooling/security/CredentialResolver.h>
# include <xmltooling/security/SecurityHelper.h>
# include <xmltooling/util/ReplayCache.h>
# include <xmltooling/util/StorageService.h>
# include <xsec/utils/XSECPlatformUtils.hpp>
using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
#else
# include "lite/SAMLConstants.h"
#endif

using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

#ifndef min
# define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

namespace {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    static vector<const Handler*> g_noHandlers;

    // Application configuration wrapper
    class SHIBSP_DLLLOCAL XMLApplication : public Application, public Remoted, public DOMPropertySet, public DOMNodeFilter
    {
    public:
        XMLApplication(const ServiceProvider*, const ProtocolProvider*, DOMElement*, const XMLApplication* base=nullptr);
        ~XMLApplication();

        const char* getHash() const {return m_hash.c_str();}

#ifndef SHIBSP_LITE
        SAMLArtifact* generateSAML1Artifact(const EntityDescriptor* relyingParty) const {
            throw ConfigurationException("No support for SAML 1.x artifact generation.");
        }
        SAML2Artifact* generateSAML2Artifact(const EntityDescriptor* relyingParty) const {
            pair<bool,int> index = make_pair(false,0);
            const PropertySet* props = getRelyingParty(relyingParty);
            index = props->getInt("artifactEndpointIndex");
            if (!index.first)
                index = getArtifactEndpointIndex();
            pair<bool,const char*> entityID = props->getString("entityID");
            return new SAML2ArtifactType0004(
                SecurityHelper::doHash("SHA1", entityID.second, strlen(entityID.second), false),
                index.first ? index.second : 1
                );
        }

        MetadataProvider* getMetadataProvider(bool required=true) const {
            if (required && !m_base && !m_metadata)
                throw ConfigurationException("No MetadataProvider available.");
            return (!m_metadata && m_base) ? m_base->getMetadataProvider(required) : m_metadata.get();
        }
        TrustEngine* getTrustEngine(bool required=true) const {
            if (required && !m_base && !m_trust)
                throw ConfigurationException("No TrustEngine available.");
            return (!m_trust && m_base) ? m_base->getTrustEngine(required) : m_trust.get();
        }
        AttributeExtractor* getAttributeExtractor() const {
            return (!m_attrExtractor && m_base) ? m_base->getAttributeExtractor() : m_attrExtractor.get();
        }
        AttributeFilter* getAttributeFilter() const {
            return (!m_attrFilter && m_base) ? m_base->getAttributeFilter() : m_attrFilter.get();
        }
        AttributeResolver* getAttributeResolver() const {
            return (!m_attrResolver && m_base) ? m_base->getAttributeResolver() : m_attrResolver.get();
        }
        CredentialResolver* getCredentialResolver() const {
            return (!m_credResolver && m_base) ? m_base->getCredentialResolver() : m_credResolver.get();
        }
        const PropertySet* getRelyingParty(const EntityDescriptor* provider) const;
        const PropertySet* getRelyingParty(const XMLCh* entityID) const;

        const vector<const XMLCh*>* getAudiences() const {
            return (m_audiences.empty() && m_base) ? m_base->getAudiences() : &m_audiences;
        }
#endif
        string getNotificationURL(const char* resource, bool front, unsigned int index) const;

        const vector<string>& getRemoteUserAttributeIds() const {
            return (m_remoteUsers.empty() && m_base) ? m_base->getRemoteUserAttributeIds() : m_remoteUsers;
        }

        void clearHeader(SPRequest& request, const char* rawname, const char* cginame) const;
        void setHeader(SPRequest& request, const char* name, const char* value) const;
        string getSecureHeader(const SPRequest& request, const char* name) const;

        const SessionInitiator* getDefaultSessionInitiator() const;
        const SessionInitiator* getSessionInitiatorById(const char* id) const;
        const Handler* getDefaultAssertionConsumerService() const;
        const Handler* getAssertionConsumerServiceByIndex(unsigned short index) const;
        const Handler* getAssertionConsumerServiceByProtocol(const XMLCh* protocol, const char* binding=nullptr) const;
        const vector<const Handler*>& getAssertionConsumerServicesByBinding(const XMLCh* binding) const;
        const Handler* getHandler(const char* path) const;
        void getHandlers(vector<const Handler*>& handlers) const;
        void limitRedirect(const GenericRequest& request, const char* url) const;

        void receive(DDF& in, ostream& out) {
            // Only current function is to return the headers to clear.
            DDF header;
            DDF ret=DDF(nullptr).list();
            DDFJanitor jret(ret);
            for (vector< pair<string,string> >::const_iterator i = m_unsetHeaders.begin(); i!=m_unsetHeaders.end(); ++i) {
                header = DDF(i->first.c_str()).string(i->second.c_str());
                ret.add(header);
            }
            out << ret;
        }

        // Provides filter to exclude special config elements.
#ifdef SHIBSP_XERCESC_SHORT_ACCEPTNODE
        short
#else
        FilterAction
#endif
        acceptNode(const DOMNode* node) const;

    private:
        template <class T> T* doChainedPlugins(
            PluginManager<T,string,const DOMElement*>& pluginMgr,
            const char* pluginType,
            const char* chainingType,
            const XMLCh* localName,
            DOMElement* e,
            Category& log,
            const char* dummyType=nullptr
            );
        void doAttributeInfo();
        void doHandlers(const ProtocolProvider*, const DOMElement*, Category&);
        void doSSO(const ProtocolProvider&, set<string>&, DOMElement*, Category&);
        void doLogout(const ProtocolProvider&, set<string>&, DOMElement*, Category&);
        void doNameIDMgmt(const ProtocolProvider&, set<string>&, DOMElement*, Category&);
        void doArtifactResolution(const ProtocolProvider&, const char*, DOMElement*, Category&);
        const XMLApplication* m_base;
        string m_hash;
        std::pair<std::string,std::string> m_attributePrefix;
#ifndef SHIBSP_LITE
        void doAttributePlugins(DOMElement*, Category&);
        scoped_ptr<MetadataProvider> m_metadata;
        scoped_ptr<TrustEngine> m_trust;
        scoped_ptr<AttributeExtractor> m_attrExtractor;
        scoped_ptr<AttributeFilter> m_attrFilter;
        scoped_ptr<AttributeResolver> m_attrResolver;
        scoped_ptr<CredentialResolver> m_credResolver;
        vector<const XMLCh*> m_audiences;

        // RelyingParty properties
        map< xstring,boost::shared_ptr<PropertySet> > m_partyMap;   // name-based matching
        vector< pair< boost::shared_ptr<EntityMatcher>,boost::shared_ptr<PropertySet> > > m_partyVec;  // plugin-based matching
#endif
        vector<string> m_remoteUsers,m_frontLogout,m_backLogout;

        // manage handler objects
        vector< boost::shared_ptr<Handler> > m_handlers;

        // maps location (path info) to applicable handlers
        map<string,const Handler*> m_handlerMap;

        // maps unique indexes to consumer services
        map<unsigned int,const Handler*> m_acsIndexMap;

        // pointer to default consumer service
        const Handler* m_acsDefault;

        // maps binding strings to supporting consumer service(s)
        typedef map< xstring,vector<const Handler*> > ACSBindingMap;
        ACSBindingMap m_acsBindingMap;

        // maps protocol strings to supporting consumer service(s)
        typedef map< xstring,vector<const Handler*> > ACSProtocolMap;
        ACSProtocolMap m_acsProtocolMap;

        // pointer to default session initiator
        const SessionInitiator* m_sessionInitDefault;

        // maps unique ID strings to session initiators
        map<string,const SessionInitiator*> m_sessionInitMap;

        // pointer to default artifact resolution service
        const Handler* m_artifactResolutionDefault;

        pair<bool,int> getArtifactEndpointIndex() const {
            if (m_artifactResolutionDefault) return m_artifactResolutionDefault->getInt("index");
            return m_base ? m_base->getArtifactEndpointIndex() : make_pair(false,0);
        }

        enum {
            REDIRECT_LIMIT_INHERIT,
            REDIRECT_LIMIT_NONE,
            REDIRECT_LIMIT_EXACT,
            REDIRECT_LIMIT_HOST,
            REDIRECT_LIMIT_WHITELIST,
            REDIRECT_LIMIT_EXACT_WHITELIST,
            REDIRECT_LIMIT_HOST_WHITELIST
        } m_redirectLimit;
        vector<string> m_redirectWhitelist;
    };

    // Top-level configuration implementation
    class SHIBSP_DLLLOCAL XMLConfig;
    class SHIBSP_DLLLOCAL XMLConfigImpl : public DOMPropertySet, public DOMNodeFilter
    {
    public:
        XMLConfigImpl(const DOMElement* e, bool first, XMLConfig* outer, Category& log);
        ~XMLConfigImpl() {
            if (m_document)
                m_document->release();
        }

#ifndef SHIBSP_LITE
        scoped_ptr<TransactionLog> m_tranLog;
        scoped_ptr<SecurityPolicyProvider> m_policy;
        vector< tuple<string,string,string> > m_transportOptions;
#endif
        scoped_ptr<RequestMapper> m_requestMapper;
        map< string,boost::shared_ptr<Application> > m_appmap;

        // Provides filter to exclude special config elements.
#ifdef SHIBSP_XERCESC_SHORT_ACCEPTNODE
        short
#else
        FilterAction
#endif
        acceptNode(const DOMNode* node) const;

        void setDocument(DOMDocument* doc) {
            m_document = doc;
        }

    private:
        void doExtensions(const DOMElement*, const char*, Category&);
        void doListener(const DOMElement*, XMLConfig*, Category&);
        void doCaching(const DOMElement*, XMLConfig*, Category&);

        DOMDocument* m_document;
    };

    class SHIBSP_DLLLOCAL XMLConfig : public ServiceProvider, public ReloadableXMLFile
#ifndef SHIBSP_LITE
        ,public Remoted
#endif
    {
    public:
        XMLConfig(const DOMElement* e) : ReloadableXMLFile(e, Category::getInstance(SHIBSP_LOGCAT".Config")) {}

        void init() {
            background_load();
        }

        ~XMLConfig() {
            shutdown();
#ifndef SHIBSP_LITE
            SAMLConfig::getConfig().setArtifactMap(nullptr);
            XMLToolingConfig::getConfig().setReplayCache(nullptr);
#endif
        }

#ifndef SHIBSP_LITE
        // Lockable
        Lockable* lock() {
            ReloadableXMLFile::lock();
            if (m_impl->m_policy)
                m_impl->m_policy->lock();
            return this;
        }
        void unlock() {
            if (m_impl->m_policy)
                m_impl->m_policy->unlock();
            ReloadableXMLFile::unlock();
        }
#endif

        // PropertySet
        const PropertySet* getParent() const { return m_impl->getParent(); }
        void setParent(const PropertySet* parent) {return m_impl->setParent(parent);}
        pair<bool,bool> getBool(const char* name, const char* ns=nullptr) const {return m_impl->getBool(name,ns);}
        pair<bool,const char*> getString(const char* name, const char* ns=nullptr) const {return m_impl->getString(name,ns);}
        pair<bool,const XMLCh*> getXMLString(const char* name, const char* ns=nullptr) const {return m_impl->getXMLString(name,ns);}
        pair<bool,unsigned int> getUnsignedInt(const char* name, const char* ns=nullptr) const {return m_impl->getUnsignedInt(name,ns);}
        pair<bool,int> getInt(const char* name, const char* ns=nullptr) const {return m_impl->getInt(name,ns);}
        void getAll(map<string,const char*>& properties) const {return m_impl->getAll(properties);}
        const PropertySet* getPropertySet(const char* name, const char* ns="urn:mace:shibboleth:2.0:native:sp:config") const {return m_impl->getPropertySet(name,ns);}
        const DOMElement* getElement() const {return m_impl->getElement();}

        // ServiceProvider
#ifndef SHIBSP_LITE
        // Remoted
        void receive(DDF& in, ostream& out);

        TransactionLog* getTransactionLog() const {
            if (m_impl->m_tranLog)
                return m_impl->m_tranLog.get();
            throw ConfigurationException("No TransactionLog available.");
        }

        StorageService* getStorageService(const char* id) const {
            if (id) {
                map< string,boost::shared_ptr<StorageService> >::const_iterator i = m_storage.find(id);
                if (i != m_storage.end())
                    return i->second.get();
            }
            else if (!m_storage.empty())
                return m_storage.begin()->second.get();
            return nullptr;
        }
#endif

        ListenerService* getListenerService(bool required=true) const {
            if (required && !m_listener)
                throw ConfigurationException("No ListenerService available.");
            return m_listener.get();
        }

        SessionCache* getSessionCache(bool required=true) const {
            if (required && !m_sessionCache)
                throw ConfigurationException("No SessionCache available.");
            return m_sessionCache.get();
        }

        RequestMapper* getRequestMapper(bool required=true) const {
            if (required && !m_impl->m_requestMapper)
                throw ConfigurationException("No RequestMapper available.");
            return m_impl->m_requestMapper.get();
        }

        const Application* getApplication(const char* applicationId) const {
            map< string,boost::shared_ptr<Application> >::const_iterator i = m_impl->m_appmap.find(applicationId ? applicationId : "default");
            return (i != m_impl->m_appmap.end()) ? i->second.get() : nullptr;
        }

#ifndef SHIBSP_LITE
        SecurityPolicyProvider* getSecurityPolicyProvider(bool required=true) const {
            if (required && !m_impl->m_policy)
                throw ConfigurationException("No SecurityPolicyProvider available.");
            return m_impl->m_policy.get();
        }

        const PropertySet* getPolicySettings(const char* id) const {
            return getSecurityPolicyProvider()->getPolicySettings(id);
        }

        const vector<const SecurityPolicyRule*>& getPolicyRules(const char* id) const {
            return getSecurityPolicyProvider()->getPolicyRules(id);
        }

        bool setTransportOptions(SOAPTransport& transport) const {
            bool ret = true;
            for (vector< tuple<string,string,string> >::const_iterator opt = m_impl->m_transportOptions.begin();
                    opt != m_impl->m_transportOptions.end(); ++opt) {
                if (!transport.setProviderOption(opt->get<0>().c_str(), opt->get<1>().c_str(), opt->get<2>().c_str())) {
                    m_log.error("failed to set SOAPTransport option (%s)", opt->get<1>().c_str());
                    ret = false;
                }
            }
            return ret;
        }
#endif

    protected:
        pair<bool,DOMElement*> background_load();

    private:
        friend class XMLConfigImpl;
        // The order of these members actually matters. If we want to rely on auto-destruction, then
        // anything dependent on anything else has to come later in the object so it will pop first.
        // Storage is the lowest, then remoting, then the cache, and finally the rest.
#ifndef SHIBSP_LITE
        map< string,boost::shared_ptr<StorageService> > m_storage;
#endif
        scoped_ptr<ListenerService> m_listener;
        scoped_ptr<SessionCache> m_sessionCache;
        scoped_ptr<XMLConfigImpl> m_impl;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    static const XMLCh applicationId[] =        UNICODE_LITERAL_13(a,p,p,l,i,c,a,t,i,o,n,I,d);
    static const XMLCh ApplicationOverride[] =  UNICODE_LITERAL_19(A,p,p,l,i,c,a,t,i,o,n,O,v,e,r,r,i,d,e);
    static const XMLCh ApplicationDefaults[] =  UNICODE_LITERAL_19(A,p,p,l,i,c,a,t,i,o,n,D,e,f,a,u,l,t,s);
    static const XMLCh _ArtifactMap[] =         UNICODE_LITERAL_11(A,r,t,i,f,a,c,t,M,a,p);
    static const XMLCh _AttributeExtractor[] =  UNICODE_LITERAL_18(A,t,t,r,i,b,u,t,e,E,x,t,r,a,c,t,o,r);
    static const XMLCh _AttributeFilter[] =     UNICODE_LITERAL_15(A,t,t,r,i,b,u,t,e,F,i,l,t,e,r);
    static const XMLCh _AttributeResolver[] =   UNICODE_LITERAL_17(A,t,t,r,i,b,u,t,e,R,e,s,o,l,v,e,r);
    static const XMLCh _AssertionConsumerService[] = UNICODE_LITERAL_24(A,s,s,e,r,t,i,o,n,C,o,n,s,u,m,e,r,S,e,r,v,i,c,e);
    static const XMLCh _ArtifactResolutionService[] =UNICODE_LITERAL_25(A,r,t,i,f,a,c,t,R,e,s,o,l,u,t,i,o,n,S,e,r,v,i,c,e);
    static const XMLCh _Audience[] =            UNICODE_LITERAL_8(A,u,d,i,e,n,c,e);
    static const XMLCh Binding[] =              UNICODE_LITERAL_7(B,i,n,d,i,n,g);
    static const XMLCh Channel[]=               UNICODE_LITERAL_7(C,h,a,n,n,e,l);
    static const XMLCh _CredentialResolver[] =  UNICODE_LITERAL_18(C,r,e,d,e,n,t,i,a,l,R,e,s,o,l,v,e,r);
    static const XMLCh _default[] =             UNICODE_LITERAL_7(d,e,f,a,u,l,t);
    static const XMLCh _Extensions[] =          UNICODE_LITERAL_10(E,x,t,e,n,s,i,o,n,s);
    static const XMLCh _fatal[] =               UNICODE_LITERAL_5(f,a,t,a,l);
    static const XMLCh _Handler[] =             UNICODE_LITERAL_7(H,a,n,d,l,e,r);
    static const XMLCh _id[] =                  UNICODE_LITERAL_2(i,d);
    static const XMLCh _index[] =               UNICODE_LITERAL_5(i,n,d,e,x);
    static const XMLCh InProcess[] =            UNICODE_LITERAL_9(I,n,P,r,o,c,e,s,s);
    static const XMLCh Library[] =              UNICODE_LITERAL_7(L,i,b,r,a,r,y);
    static const XMLCh Listener[] =             UNICODE_LITERAL_8(L,i,s,t,e,n,e,r);
    static const XMLCh Location[] =             UNICODE_LITERAL_8(L,o,c,a,t,i,o,n);
    static const XMLCh logger[] =               UNICODE_LITERAL_6(l,o,g,g,e,r);
    static const XMLCh Logout[] =               UNICODE_LITERAL_6(L,o,g,o,u,t);
    static const XMLCh _LogoutInitiator[] =     UNICODE_LITERAL_15(L,o,g,o,u,t,I,n,i,t,i,a,t,o,r);
    static const XMLCh _ManageNameIDService[] = UNICODE_LITERAL_19(M,a,n,a,g,e,N,a,m,e,I,D,S,e,r,v,i,c,e);
    static const XMLCh _MetadataProvider[] =    UNICODE_LITERAL_16(M,e,t,a,d,a,t,a,P,r,o,v,i,d,e,r);
    static const XMLCh NameIDMgmt[] =           UNICODE_LITERAL_10(N,a,m,e,I,D,M,g,m,t);
    static const XMLCh Notify[] =               UNICODE_LITERAL_6(N,o,t,i,f,y);
    static const XMLCh _option[] =              UNICODE_LITERAL_6(o,p,t,i,o,n);
    static const XMLCh OutOfProcess[] =         UNICODE_LITERAL_12(O,u,t,O,f,P,r,o,c,e,s,s);
    static const XMLCh _path[] =                UNICODE_LITERAL_4(p,a,t,h);
    static const XMLCh _policyId[] =            UNICODE_LITERAL_8(p,o,l,i,c,y,I,d);
    static const XMLCh _ProtocolProvider[] =    UNICODE_LITERAL_16(P,r,o,t,o,c,o,l,P,r,o,v,i,d,e,r);
    static const XMLCh _provider[] =            UNICODE_LITERAL_8(p,r,o,v,i,d,e,r);
    static const XMLCh RelyingParty[] =         UNICODE_LITERAL_12(R,e,l,y,i,n,g,P,a,r,t,y);
    static const XMLCh _ReplayCache[] =         UNICODE_LITERAL_11(R,e,p,l,a,y,C,a,c,h,e);
    static const XMLCh _RequestMapper[] =       UNICODE_LITERAL_13(R,e,q,u,e,s,t,M,a,p,p,e,r);
    static const XMLCh RequestMap[] =           UNICODE_LITERAL_10(R,e,q,u,e,s,t,M,a,p);
    static const XMLCh SecurityPolicies[] =     UNICODE_LITERAL_16(S,e,c,u,r,i,t,y,P,o,l,i,c,i,e,s);
    static const XMLCh _SecurityPolicyProvider[] = UNICODE_LITERAL_22(S,e,c,u,r,i,t,y,P,o,l,i,c,y,P,r,o,v,i,d,e,r);
    static const XMLCh _SessionCache[] =        UNICODE_LITERAL_12(S,e,s,s,i,o,n,C,a,c,h,e);
    static const XMLCh _SessionInitiator[] =    UNICODE_LITERAL_16(S,e,s,s,i,o,n,I,n,i,t,i,a,t,o,r);
    static const XMLCh _SingleLogoutService[] = UNICODE_LITERAL_19(S,i,n,g,l,e,L,o,g,o,u,t,S,e,r,v,i,c,e);
    static const XMLCh Site[] =                 UNICODE_LITERAL_4(S,i,t,e);
    static const XMLCh SSO[] =                  UNICODE_LITERAL_3(S,S,O);
    static const XMLCh _StorageService[] =      UNICODE_LITERAL_14(S,t,o,r,a,g,e,S,e,r,v,i,c,e);
    static const XMLCh TCPListener[] =          UNICODE_LITERAL_11(T,C,P,L,i,s,t,e,n,e,r);
    static const XMLCh tranLogFiller[] =        UNICODE_LITERAL_13(t,r,a,n,L,o,g,F,i,l,l,e,r);
    static const XMLCh tranLogFormat[] =        UNICODE_LITERAL_13(t,r,a,n,L,o,g,F,o,r,m,a,t);
    static const XMLCh TransportOption[] =      UNICODE_LITERAL_15(T,r,a,n,s,p,o,r,t,O,p,t,i,o,n);
    static const XMLCh _TrustEngine[] =         UNICODE_LITERAL_11(T,r,u,s,t,E,n,g,i,n,e);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);
    static const XMLCh UnixListener[] =         UNICODE_LITERAL_12(U,n,i,x,L,i,s,t,e,n,e,r);
};

namespace shibsp {
    ServiceProvider* XMLServiceProviderFactory(const DOMElement* const & e)
    {
        return new XMLConfig(e);
    }
};

XMLApplication::XMLApplication(
    const ServiceProvider* sp,
    const ProtocolProvider* pp,
    DOMElement* e,
    const XMLApplication* base
    ) : Application(sp), m_base(base), m_acsDefault(nullptr), m_sessionInitDefault(nullptr), m_artifactResolutionDefault(nullptr)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("XMLApplication");
#endif
    Category& log = Category::getInstance(SHIBSP_LOGCAT".Application");

    // First load any property sets.
    map<string,string> remapper;
    remapper["relayStateLimit"] = "redirectLimit";
    remapper["relayStateWhitelist"] = "redirectWhitelist";
    load(e, nullptr, this, &remapper);

    // Process redirect limit policy. Do this before assigning the parent pointer
    // to ensure we get only our Sessions element.
    const PropertySet* sessionProps = getPropertySet("Sessions");
    if (sessionProps) {
        pair<bool,const char*> prop = sessionProps->getString("redirectLimit");
        if (prop.first) {
            if (!strcmp(prop.second, "none"))
                m_redirectLimit = REDIRECT_LIMIT_NONE;
            else if (!strcmp(prop.second, "exact"))
                m_redirectLimit = REDIRECT_LIMIT_EXACT;
            else if (!strcmp(prop.second, "host"))
                m_redirectLimit = REDIRECT_LIMIT_HOST;
            else {
                if (!strcmp(prop.second, "exact+whitelist"))
                    m_redirectLimit = REDIRECT_LIMIT_EXACT_WHITELIST;
                else if (!strcmp(prop.second, "host+whitelist"))
                    m_redirectLimit = REDIRECT_LIMIT_HOST_WHITELIST;
                else if (!strcmp(prop.second, "whitelist"))
                    m_redirectLimit = REDIRECT_LIMIT_WHITELIST;
                else
                    throw ConfigurationException("Unrecognized redirectLimit setting ($1)", params(1, prop.second));
                prop = sessionProps->getString("redirectWhitelist");
                if (prop.first) {
                    string dup(prop.second);
                    split(m_redirectWhitelist, dup, is_space(), algorithm::token_compress_on);
                }
            }
        }
        else {
            m_redirectLimit = base ? REDIRECT_LIMIT_INHERIT : REDIRECT_LIMIT_NONE;
        }

        // Audit some additional settings for logging purposes.
        prop = sessionProps->getString("cookieProps");
        if (!prop.first) {
            log.warn("empty/missing cookieProps setting, set to \"https\" for SSL/TLS-only usage");
        }
        else if (!strcmp(prop.second, "http")) {
            log.warn("insecure cookieProps setting, set to \"https\" for SSL/TLS-only usage");
        }
        else if (strcmp(prop.second, "https")) {
            if (!strstr(prop.second, ";secure") && !strstr(prop.second, "; secure"))
                log.warn("custom cookieProps setting should include \"; secure\" for SSL/TLS-only usage");
            else if (!strstr(prop.second, ";HttpOnly") && !strstr(prop.second, "; HttpOnly"))
                log.warn("custom cookieProps setting should include \"; HttpOnly\", site is vulnerable to client-side cookie theft");
        }

        pair<bool,bool> handlerSSL = sessionProps->getBool("handlerSSL");
        if (handlerSSL.first && !handlerSSL.second)
            log.warn("handlerSSL should be enabled for SSL/TLS-enabled web sites");
    }
    else {
        m_redirectLimit = base ? REDIRECT_LIMIT_INHERIT : REDIRECT_LIMIT_NONE;
    }

    // Assign parent.
    if (base)
        setParent(base);

    SPConfig& conf=SPConfig::getConfig();
#ifndef SHIBSP_LITE
    XMLToolingConfig& xmlConf=XMLToolingConfig::getConfig();
#endif

    // This used to be an actual hash, but now it's just a hex-encode to avoid xmlsec dependency.
    static char DIGITS[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    string tohash=getId();
    tohash+=getString("entityID").second;
    for (const char* ch = tohash.c_str(); *ch; ++ch) {
        m_hash += (DIGITS[((unsigned char)(0xF0 & *ch)) >> 4 ]);
        m_hash += (DIGITS[0x0F & *ch]);
    }

    doAttributeInfo();

    if (conf.isEnabled(SPConfig::Handlers))
        doHandlers(pp, e, log);

    // Notification.
    DOMNodeList* nlist = e->getElementsByTagNameNS(shibspconstants::SHIB2SPCONFIG_NS, Notify);
    for (XMLSize_t i = 0; nlist && i < nlist->getLength(); ++i) {
        if (nlist->item(i)->getParentNode()->isSameNode(e)) {
            const XMLCh* channel = static_cast<DOMElement*>(nlist->item(i))->getAttributeNS(nullptr, Channel);
            string loc(XMLHelper::getAttrString(static_cast<DOMElement*>(nlist->item(i)), nullptr, Location));
            if (!loc.empty()) {
                if (channel && *channel == chLatin_f)
                    m_frontLogout.push_back(loc);
                else
                    m_backLogout.push_back(loc);
            }
        }
    }

#ifndef SHIBSP_LITE
    nlist = e->getElementsByTagNameNS(samlconstants::SAML20_NS, Audience::LOCAL_NAME);
    if (nlist && nlist->getLength()) {
        log.warn("use of <saml:Audience> elements outside of a Security Policy Rule is deprecated");
        for (XMLSize_t i = 0; i < nlist->getLength(); ++i)
            if (nlist->item(i)->getParentNode()->isSameNode(e) && nlist->item(i)->hasChildNodes())
                m_audiences.push_back(nlist->item(i)->getFirstChild()->getNodeValue());
    }

    if (conf.isEnabled(SPConfig::Metadata)) {
        m_metadata.reset(
            doChainedPlugins(
                SAMLConfig::getConfig().MetadataProviderManager, "MetadataProvider", CHAINING_METADATA_PROVIDER, _MetadataProvider, e, log
                )
            );
        try {
            if (m_metadata)
                m_metadata->init();
            else if (!m_base)
                log.warn("no MetadataProvider available, configure at least one for standard SSO usage");
        }
        catch (std::exception& ex) {
            log.crit("error initializing MetadataProvider: %s", ex.what());
        }
    }

    if (conf.isEnabled(SPConfig::Trust)) {
        m_trust.reset(doChainedPlugins(xmlConf.TrustEngineManager, "TrustEngine", CHAINING_TRUSTENGINE, _TrustEngine, e, log));
        if (!m_trust && !m_base) {
            log.info(
                "no TrustEngine specified or installed, using default chain {%s, %s}",
                EXPLICIT_KEY_TRUSTENGINE, SHIBBOLETH_PKIX_TRUSTENGINE
                );
            m_trust.reset(xmlConf.TrustEngineManager.newPlugin(CHAINING_TRUSTENGINE, nullptr));
            ChainingTrustEngine* trustchain = dynamic_cast<ChainingTrustEngine*>(m_trust.get());
            if (trustchain) {
                trustchain->addTrustEngine(xmlConf.TrustEngineManager.newPlugin(EXPLICIT_KEY_TRUSTENGINE, nullptr));
                trustchain->addTrustEngine(xmlConf.TrustEngineManager.newPlugin(SHIBBOLETH_PKIX_TRUSTENGINE, nullptr));
            }
        }
    }

    if (conf.isEnabled(SPConfig::AttributeResolution)) {
        doAttributePlugins(e, log);
    }

    if (conf.isEnabled(SPConfig::Credentials)) {
        m_credResolver.reset(
            doChainedPlugins(xmlConf.CredentialResolverManager, "CredentialResolver", CHAINING_CREDENTIAL_RESOLVER, _CredentialResolver, e, log)
            );
    }

    // Finally, load relying parties.
    const DOMElement* child = XMLHelper::getFirstChildElement(e, RelyingParty);
    while (child) {
        if (child->hasAttributeNS(nullptr, saml2::Attribute::NAME_ATTRIB_NAME)) {
            boost::shared_ptr<DOMPropertySet> rp(new DOMPropertySet());
            rp->load(child, nullptr, this);
            rp->setParent(this);
            m_partyMap[child->getAttributeNS(nullptr, saml2::Attribute::NAME_ATTRIB_NAME)] = rp;
        }
        else if (child->hasAttributeNS(nullptr, _type)) {
            string emtype(XMLHelper::getAttrString(child, nullptr, _type));
            boost::shared_ptr<EntityMatcher> em(SAMLConfig::getConfig().EntityMatcherManager.newPlugin(emtype, child));
            boost::shared_ptr<DOMPropertySet> rp(new DOMPropertySet());
            rp->load(child, nullptr, this);
            rp->setParent(this);
            m_partyVec.push_back(make_pair(em, rp));
        }
        child = XMLHelper::getNextSiblingElement(child, RelyingParty);
    }
    if (base && m_partyMap.empty() && m_partyVec.empty() && (!base->m_partyMap.empty() || !base->m_partyVec.empty())) {
        // For inheritance of RPs to work, we have to pull them in to the override by cloning the DOM.
        child = XMLHelper::getFirstChildElement(base->getElement(), RelyingParty);
        while (child) {
            if (child->hasAttributeNS(nullptr, saml2::Attribute::NAME_ATTRIB_NAME)) {
                DOMElement* rpclone = static_cast<DOMElement*>(child->cloneNode(true));
                boost::shared_ptr<DOMPropertySet> rp(new DOMPropertySet());
                rp->load(rpclone, nullptr, this);
                rp->setParent(this);
                m_partyMap[rpclone->getAttributeNS(nullptr, saml2::Attribute::NAME_ATTRIB_NAME)] = rp;
            }
            else if (child->hasAttributeNS(nullptr, _type)) {
                DOMElement* rpclone = static_cast<DOMElement*>(child->cloneNode(true));
                string emtype(XMLHelper::getAttrString(rpclone, nullptr, _type));
                boost::shared_ptr<EntityMatcher> em(SAMLConfig::getConfig().EntityMatcherManager.newPlugin(emtype, rpclone));
                boost::shared_ptr<DOMPropertySet> rp(new DOMPropertySet());
                rp->load(rpclone, nullptr, this);
                rp->setParent(this);
                m_partyVec.push_back(make_pair(em, rp));
            }
            child = XMLHelper::getNextSiblingElement(child, RelyingParty);
        }
    }
#endif

    // Out of process only, we register a listener endpoint.
    if (!conf.isEnabled(SPConfig::InProcess)) {
        ListenerService* listener = sp->getListenerService(false);
        if (listener) {
            string addr=string(getId()) + "::getHeaders::Application";
            listener->regListener(addr.c_str(), this);
        }
        else {
            log.info("no ListenerService available, Application remoting disabled");
        }
    }
}

XMLApplication::~XMLApplication()
{
    ListenerService* listener=getServiceProvider().getListenerService(false);
    if (listener && SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess) && !SPConfig::getConfig().isEnabled(SPConfig::InProcess)) {
        string addr=string(getId()) + "::getHeaders::Application";
        listener->unregListener(addr.c_str(), this);
    }
}

template <class T> T* XMLApplication::doChainedPlugins(
    PluginManager<T,string,const DOMElement*>& pluginMgr,
    const char* pluginType,
    const char* chainingType,
    const XMLCh* localName,
    DOMElement* e,
    Category& log,
    const char* dummyType
    )
{
    string t;
    DOMElement* child = XMLHelper::getFirstChildElement(e, localName);
    if (child) {
        // Check for multiple.
        if (XMLHelper::getNextSiblingElement(child, localName)) {
            log.info("multiple %s plugins, wrapping in a chain", pluginType);
            DOMElement* chain = child->getOwnerDocument()->createElementNS(nullptr, localName);
            while (child) {
                chain->appendChild(child);
                child = XMLHelper::getFirstChildElement(e, localName);
            }
            t = chainingType;
            child = chain;
            e->appendChild(chain);
        }
        else {
            // Only a single one.
            t = XMLHelper::getAttrString(child, nullptr, _type);
        }

        try {
            if (!t.empty()) {
                log.info("building %s of type %s...", pluginType, t.c_str());
                return pluginMgr.newPlugin(t.c_str(), child);
            }
            else {
                throw ConfigurationException("$1 element had no type attribute.", params(1, pluginType));
            }
        }
        catch (std::exception& ex) {
            log.crit("error building %s: %s", pluginType, ex.what());
            if (dummyType) {
                // Install a dummy version as a safety valve.
                log.crit("installing safe %s in place of failed version", pluginType);
                return pluginMgr.newPlugin(dummyType, nullptr);
            }
        }
    }

    return nullptr;
}

void XMLApplication::doAttributeInfo()
{
    // Populate prefix pair.
    m_attributePrefix.second = "HTTP_";
    pair<bool,const char*> prefix = getString("attributePrefix");
    if (prefix.first) {
        m_attributePrefix.first = prefix.second;
        const char* pch = prefix.second;
        while (*pch) {
            m_attributePrefix.second += (isalnum(*pch) ? toupper(*pch) : '_');
            pch++;
        }
    }

    pair<bool,const char*> attributes = getString("REMOTE_USER");
    if (attributes.first) {
        string dup(attributes.second);
        split(m_remoteUsers, dup, is_space(), algorithm::token_compress_on);
    }

    // Load attribute ID lists for REMOTE_USER and header clearing.
    if (SPConfig::getConfig().isEnabled(SPConfig::InProcess)) {
        attributes = getString("unsetHeaders");
        if (attributes.first) {
            string transformedprefix(m_attributePrefix.second);
            const char* pch;
            prefix = getString("metadataAttributePrefix");
            if (prefix.first) {
                pch = prefix.second;
                while (*pch) {
                    transformedprefix += (isalnum(*pch) ? toupper(*pch) : '_');
                    pch++;
                }
            }

            string dup(attributes.second);
            vector<string> headerNames;
            split(headerNames, dup, is_space(), algorithm::token_compress_on);
            for (vector<string>::const_iterator h = headerNames.begin(); h != headerNames.end(); ++h) {
                string transformed;
                const char* pch = h->c_str();
                while (*pch) {
                    transformed += (isalnum(*pch) ? toupper(*pch) : '_');
                    pch++;
                }
                m_unsetHeaders.push_back(pair<string,string>(m_attributePrefix.first + *h, m_attributePrefix.second + transformed));
                if (prefix.first)
                    m_unsetHeaders.push_back(pair<string,string>(m_attributePrefix.first + prefix.second + *h, transformedprefix + transformed));
            }
            m_unsetHeaders.push_back(pair<string,string>(m_attributePrefix.first + "Shib-Application-ID", m_attributePrefix.second + "SHIB_APPLICATION_ID"));
        }
    }
}

void XMLApplication::doHandlers(const ProtocolProvider* pp, const DOMElement* e, Category& log)
{
    SPConfig& conf = SPConfig::getConfig();

    const PropertySet* sessions = getPropertySet("Sessions");

    // Process assertion export handler.
    pair<bool,const char*> location = sessions ? sessions->getString("exportLocation") : pair<bool,const char*>(false,nullptr);
    if (location.first) {
        try {
            DOMElement* exportElement = e->getOwnerDocument()->createElementNS(shibspconstants::SHIB2SPCONFIG_NS, _Handler);
            exportElement->setAttributeNS(nullptr,Location,sessions->getXMLString("exportLocation").second);
            pair<bool,const XMLCh*> exportACL = sessions->getXMLString("exportACL");
            if (exportACL.first) {
                static const XMLCh _acl[] = UNICODE_LITERAL_9(e,x,p,o,r,t,A,C,L);
                exportElement->setAttributeNS(nullptr,_acl,exportACL.second);
            }
            boost::shared_ptr<Handler> exportHandler(
                conf.HandlerManager.newPlugin(samlconstants::SAML20_BINDING_URI, pair<const DOMElement*,const char*>(exportElement, getId()))
                );
            m_handlers.push_back(exportHandler);

            // Insert into location map. If it contains the handlerURL, we skip past that part.
            const char* hurl = sessions->getString("handlerURL").second;
            if (!hurl)
                hurl = "/Shibboleth.sso";
            const char* pch = strstr(location.second, hurl);
            if (pch)
                location.second = pch + strlen(hurl);
            if (*location.second == '/')
                m_handlerMap[location.second] = exportHandler.get();
            else
                m_handlerMap[string("/") + location.second] = exportHandler.get();
        }
        catch (std::exception& ex) {
            log.error("caught exception installing assertion lookup handler: %s", ex.what());
        }
    }

    // Look for "shorthand" elements first.
    set<string> protocols;
    DOMElement* child = sessions ? XMLHelper::getFirstChildElement(sessions->getElement()) : nullptr;
    while (child) {
        if (XMLHelper::isNodeNamed(child, shibspconstants::SHIB2SPCONFIG_NS, SSO)) {
            if (pp)
                doSSO(*pp, protocols, child, log);
            else
                log.error("no ProtocolProvider, SSO auto-configure unsupported");
        }
        else if (XMLHelper::isNodeNamed(child, shibspconstants::SHIB2SPCONFIG_NS, Logout)) {
            if (pp)
                doLogout(*pp, protocols, child, log);
            else
                log.error("no ProtocolProvider, Logout auto-configure unsupported");
        }
        else if (XMLHelper::isNodeNamed(child, shibspconstants::SHIB2SPCONFIG_NS, NameIDMgmt)) {
            if (pp)
                doNameIDMgmt(*pp, protocols, child, log);
            else
                log.error("no ProtocolProvider, NameIDMgmt auto-configure unsupported");
        }
        else {
            break;  // drop into next while loop
        }
        child = XMLHelper::getNextSiblingElement(child);
    }

    // Process other handlers.
    bool hardACS=false, hardSessionInit=false, hardArt=false;
    while (child) {
        if (!child->hasAttributeNS(nullptr, Location)) {
            auto_ptr_char hclass(child->getLocalName());
            log.error("%s handler with no Location property cannot be processed", hclass.get());
            child = XMLHelper::getNextSiblingElement(child);
            continue;
        }
        try {
            boost::shared_ptr<Handler> handler;
            if (XMLString::equals(child->getLocalName(), _AssertionConsumerService)) {
                string bindprop(XMLHelper::getAttrString(child, nullptr, Binding));
                if (bindprop.empty()) {
                    log.error("AssertionConsumerService element has no Binding attribute, skipping it...");
                    child = XMLHelper::getNextSiblingElement(child);
                    continue;
                }
                handler.reset(conf.AssertionConsumerServiceManager.newPlugin(bindprop.c_str(), pair<const DOMElement*,const char*>(child, getId())));
                // Map by binding and protocol (may be > 1 per protocol and binding)
                m_acsBindingMap[handler->getXMLString("Binding").second].push_back(handler.get());
                const XMLCh* protfamily = handler->getProtocolFamily();
                if (protfamily)
                    m_acsProtocolMap[protfamily].push_back(handler.get());
                m_acsIndexMap[handler->getUnsignedInt("index").second] = handler.get();

                if (!hardACS) {
                    pair<bool,bool> defprop = handler->getBool("isDefault");
                    if (defprop.first) {
                        if (defprop.second) {
                            hardACS = true;
                            m_acsDefault = handler.get();
                        }
                    }
                    else if (!m_acsDefault)
                        m_acsDefault = handler.get();
                }
            }
            else if (XMLString::equals(child->getLocalName(), _SessionInitiator)) {
                string t(XMLHelper::getAttrString(child, nullptr, _type));
                if (t.empty()) {
                    log.error("SessionInitiator element has no type attribute, skipping it...");
                    child = XMLHelper::getNextSiblingElement(child);
                    continue;
                }
                boost::shared_ptr<SessionInitiator> sihandler(
                    conf.SessionInitiatorManager.newPlugin(t.c_str(), pair<const DOMElement*,const char*>(child, getId()))
                    );
                handler = sihandler;
                pair<bool,const char*> si_id = handler->getString("id");
                if (si_id.first && si_id.second)
                    m_sessionInitMap[si_id.second] = sihandler.get();
                if (!hardSessionInit) {
                    pair<bool,bool> defprop = handler->getBool("isDefault");
                    if (defprop.first) {
                        if (defprop.second) {
                            hardSessionInit = true;
                            m_sessionInitDefault = sihandler.get();
                        }
                    }
                    else if (!m_sessionInitDefault) {
                        m_sessionInitDefault = sihandler.get();
                    }
                }
            }
            else if (XMLString::equals(child->getLocalName(), _LogoutInitiator)) {
                string t(XMLHelper::getAttrString(child, nullptr, _type));
                if (t.empty()) {
                    log.error("LogoutInitiator element has no type attribute, skipping it...");
                    child = XMLHelper::getNextSiblingElement(child);
                    continue;
                }
                handler.reset(conf.LogoutInitiatorManager.newPlugin(t.c_str(), pair<const DOMElement*,const char*>(child, getId())));
            }
            else if (XMLString::equals(child->getLocalName(), _ArtifactResolutionService)) {
                string bindprop(XMLHelper::getAttrString(child, nullptr, Binding));
                if (bindprop.empty()) {
                    log.error("ArtifactResolutionService element has no Binding attribute, skipping it...");
                    child = XMLHelper::getNextSiblingElement(child);
                    continue;
                }
                handler.reset(conf.ArtifactResolutionServiceManager.newPlugin(bindprop.c_str(), pair<const DOMElement*,const char*>(child, getId())));

                if (!hardArt) {
                    pair<bool,bool> defprop = handler->getBool("isDefault");
                    if (defprop.first) {
                        if (defprop.second) {
                            hardArt = true;
                            m_artifactResolutionDefault = handler.get();
                        }
                    }
                    else if (!m_artifactResolutionDefault)
                        m_artifactResolutionDefault = handler.get();
                }
            }
            else if (XMLString::equals(child->getLocalName(), _SingleLogoutService)) {
                string bindprop(XMLHelper::getAttrString(child, nullptr, Binding));
                if (bindprop.empty()) {
                    log.error("SingleLogoutService element has no Binding attribute, skipping it...");
                    child = XMLHelper::getNextSiblingElement(child);
                    continue;
                }
                handler.reset(conf.SingleLogoutServiceManager.newPlugin(bindprop.c_str(), pair<const DOMElement*,const char*>(child, getId())));
            }
            else if (XMLString::equals(child->getLocalName(), _ManageNameIDService)) {
                string bindprop(XMLHelper::getAttrString(child, nullptr, Binding));
                if (bindprop.empty()) {
                    log.error("ManageNameIDService element has no Binding attribute, skipping it...");
                    child = XMLHelper::getNextSiblingElement(child);
                    continue;
                }
                handler.reset(conf.ManageNameIDServiceManager.newPlugin(bindprop.c_str(), pair<const DOMElement*,const char*>(child, getId())));
            }
            else {
                string t(XMLHelper::getAttrString(child, nullptr, _type));
                if (t.empty()) {
                    log.error("Handler element has no type attribute, skipping it...");
                    child = XMLHelper::getNextSiblingElement(child);
                    continue;
                }
                handler.reset(conf.HandlerManager.newPlugin(t.c_str(), pair<const DOMElement*,const char*>(child, getId())));
            }

            m_handlers.push_back(handler);

            // Insert into location map.
            location = handler->getString("Location");
            if (location.first && *location.second == '/')
                m_handlerMap[location.second] = handler.get();
            else if (location.first)
                m_handlerMap[string("/") + location.second] = handler.get();
        }
        catch (std::exception& ex) {
            log.error("caught exception processing handler element: %s", ex.what());
        }

        child = XMLHelper::getNextSiblingElement(child);
    }
}

void XMLApplication::doSSO(const ProtocolProvider& pp, set<string>& protocols, DOMElement* e, Category& log)
{
    if (!e->hasChildNodes())
        return;
    DOMNamedNodeMap* ssoprops = e->getAttributes();
    XMLSize_t ssopropslen = ssoprops ? ssoprops->getLength() : 0;

    SPConfig& conf = SPConfig::getConfig();

    int index = 0; // track ACS indexes globally across all protocols

    // Tokenize the protocol list inside the element.
    XMLStringTokenizer prottokens(e->getTextContent());
    while (prottokens.hasMoreTokens()) {
        auto_ptr_char prot(prottokens.nextToken());

        // Look for initiator.
        const PropertySet* initiator = pp.getInitiator(prot.get(), "SSO");
        if (initiator) {
            log.info("auto-configuring SSO initiation for protocol (%s)", prot.get());
            pair<bool,const XMLCh*> inittype = initiator->getXMLString("id");
            if (inittype.first) {
                // Append a session initiator element of the designated type to the root element.
                DOMElement* sidom = e->getOwnerDocument()->createElementNS(shibspconstants::SHIB2SPCONFIG_NS, _SessionInitiator);
                sidom->setAttributeNS(nullptr, _type, inittype.second);
                e->appendChild(sidom);
                log.info("adding SessionInitiator of type (%s) to chain (/Login)", initiator->getString("id").second);

                doArtifactResolution(pp, prot.get(), e, log);
                protocols.insert(prot.get());
            }
            else {
                log.error("missing id property on Initiator element, check config for protocol (%s)", prot.get());
            }
        }

        // Look for incoming bindings.
        const vector<const PropertySet*>& bindings = pp.getBindings(prot.get(), "SSO");
        if (!bindings.empty()) {
            log.info("auto-configuring SSO endpoints for protocol (%s)", prot.get());
            pair<bool,const XMLCh*> idprop,pathprop;
            for (vector<const PropertySet*>::const_iterator b = bindings.begin(); b != bindings.end(); ++b, ++index) {
                idprop = (*b)->getXMLString("id");
                pathprop = (*b)->getXMLString("path");
                if (idprop.first && pathprop.first) {
                    DOMElement* acsdom = e->getOwnerDocument()->createElementNS(samlconstants::SAML20MD_NS, _AssertionConsumerService);

                    // Copy in any attributes from the <SSO> element so they can be accessed as properties in the ACS handler.
                    for (XMLSize_t p = 0; p < ssopropslen; ++p) {
                        DOMNode* ssoprop = ssoprops->item(p);
                        if (ssoprop->getNodeType() == DOMNode::ATTRIBUTE_NODE) {
                            acsdom->setAttributeNS(
                                ((DOMAttr*)ssoprop)->getNamespaceURI(),
                                ((DOMAttr*)ssoprop)->getLocalName(),
                                ((DOMAttr*)ssoprop)->getValue()
                                );
                        }
                    }

                    // Set necessary properties based on context.
                    acsdom->setAttributeNS(nullptr, Binding, idprop.second);
                    acsdom->setAttributeNS(nullptr, Location, pathprop.second);
                    xstring indexbuf(1, chDigit_1 + (index % 10));
                    if (index / 10)
                        indexbuf = (XMLCh)(chDigit_1 + (index / 10)) + indexbuf;
                    acsdom->setAttributeNS(nullptr, _index, indexbuf.c_str());

                    log.info("adding AssertionConsumerService for Binding (%s) at (%s)", (*b)->getString("id").second, (*b)->getString("path").second);
                    boost::shared_ptr<Handler> handler(
                        conf.AssertionConsumerServiceManager.newPlugin(
                            (*b)->getString("id").second, pair<const DOMElement*,const char*>(acsdom, getId())
                            )
                        );
                    m_handlers.push_back(handler);

                    // Setup maps and defaults.
                    m_acsBindingMap[handler->getXMLString("Binding").second].push_back(handler.get());
                    const XMLCh* protfamily = handler->getProtocolFamily();
                    if (protfamily)
                        m_acsProtocolMap[protfamily].push_back(handler.get());
                    m_acsIndexMap[handler->getUnsignedInt("index").second] = handler.get();
                    if (!m_acsDefault)
                        m_acsDefault = handler.get();

                    // Insert into location map.
                    pair<bool,const char*> location = handler->getString("Location");
                    if (location.first && *location.second == '/')
                        m_handlerMap[location.second] = handler.get();
                    else if (location.first)
                        m_handlerMap[string("/") + location.second] = handler.get();
                }
                else {
                    log.error("missing id or path property on Binding element, check config for protocol (%s)", prot.get());
                }
            }
        }

        if (!initiator && bindings.empty()) {
            log.error("no SSO Initiator or Binding config for protocol (%s)", prot.get());
        }
    }

    // Handle discovery.
    static const XMLCh discoveryProtocol[] = UNICODE_LITERAL_17(d,i,s,c,o,v,e,r,y,P,r,o,t,o,c,o,l);
    static const XMLCh discoveryURL[] = UNICODE_LITERAL_12(d,i,s,c,o,v,e,r,y,U,R,L);
    static const XMLCh _URL[] = UNICODE_LITERAL_3(U,R,L);
    const XMLCh* discop = e->getAttributeNS(nullptr, discoveryProtocol);
    if (discop && *discop) {
        const XMLCh* discou = e->getAttributeNS(nullptr, discoveryURL);
        if (discou && *discou) {
            // Append a session initiator element of the designated type to the root element.
            DOMElement* sidom = e->getOwnerDocument()->createElementNS(shibspconstants::SHIB2SPCONFIG_NS, _SessionInitiator);
            sidom->setAttributeNS(nullptr, _type, discop);
            sidom->setAttributeNS(nullptr, _URL, discou);
            e->appendChild(sidom);
            if (log.isInfoEnabled()) {
                auto_ptr_char dp(discop);
                log.info("adding SessionInitiator of type (%s) to chain (/Login)", dp.get());
            }
        }
        else {
            log.error("SSO discoveryProtocol specified without discoveryURL");
        }
    }

    // Attach default Location to SSO element.
    static const XMLCh _loc[] = { chForwardSlash, chLatin_L, chLatin_o, chLatin_g, chLatin_i, chLatin_n, chNull };
    e->setAttributeNS(nullptr, Location, _loc);

    // Instantiate Chaining initiator around the SSO element.
    boost::shared_ptr<SessionInitiator> chain(
        conf.SessionInitiatorManager.newPlugin(CHAINING_SESSION_INITIATOR, pair<const DOMElement*,const char*>(e, getId()))
        );
    m_handlers.push_back(chain);
    m_sessionInitDefault = chain.get();
    m_handlerMap["/Login"] = chain.get();
}

void XMLApplication::doLogout(const ProtocolProvider& pp, set<string>& protocols, DOMElement* e, Category& log)
{
    if (!e->hasChildNodes())
        return;
    DOMNamedNodeMap* sloprops = e->getAttributes();
    XMLSize_t slopropslen = sloprops ? sloprops->getLength() : 0;

    SPConfig& conf = SPConfig::getConfig();

    // Tokenize the protocol list inside the element.
    XMLStringTokenizer prottokens(e->getTextContent());
    while (prottokens.hasMoreTokens()) {
        auto_ptr_char prot(prottokens.nextToken());

        // Look for initiator.
        const PropertySet* initiator = pp.getInitiator(prot.get(), "Logout");
        if (initiator) {
            log.info("auto-configuring Logout initiation for protocol (%s)", prot.get());
            pair<bool,const XMLCh*> inittype = initiator->getXMLString("id");
            if (inittype.first) {
                // Append a logout initiator element of the designated type to the root element.
                DOMElement* lidom = e->getOwnerDocument()->createElementNS(shibspconstants::SHIB2SPCONFIG_NS, _LogoutInitiator);
                lidom->setAttributeNS(nullptr, _type, inittype.second);
                e->appendChild(lidom);
                log.info("adding LogoutInitiator of type (%s) to chain (/Logout)", initiator->getString("id").second);

                if (protocols.count(prot.get()) == 0) {
                    doArtifactResolution(pp, prot.get(), e, log);
                    protocols.insert(prot.get());
                }
            }
            else {
                log.error("missing id property on Initiator element, check config for protocol (%s)", prot.get());
            }
        }

        // Look for incoming bindings.
        const vector<const PropertySet*>& bindings = pp.getBindings(prot.get(), "Logout");
        if (!bindings.empty()) {
            log.info("auto-configuring Logout endpoints for protocol (%s)", prot.get());
            pair<bool,const XMLCh*> idprop,pathprop;
            for (vector<const PropertySet*>::const_iterator b = bindings.begin(); b != bindings.end(); ++b) {
                idprop = (*b)->getXMLString("id");
                pathprop = (*b)->getXMLString("path");
                if (idprop.first && pathprop.first) {
                    DOMElement* slodom = e->getOwnerDocument()->createElementNS(samlconstants::SAML20MD_NS, _SingleLogoutService);

                    // Copy in any attributes from the <Logout> element so they can be accessed as properties in the SLO handler.
                    for (XMLSize_t p = 0; p < slopropslen; ++p) {
                        DOMNode* sloprop = sloprops->item(p);
                        if (sloprop->getNodeType() == DOMNode::ATTRIBUTE_NODE) {
                            slodom->setAttributeNS(
                                ((DOMAttr*)sloprop)->getNamespaceURI(),
                                ((DOMAttr*)sloprop)->getLocalName(),
                                ((DOMAttr*)sloprop)->getValue()
                                );
                        }
                    }

                    // Set necessary properties based on context.
                    slodom->setAttributeNS(nullptr, Binding, idprop.second);
                    slodom->setAttributeNS(nullptr, Location, pathprop.second);
                    if (e->hasAttributeNS(nullptr, _policyId))
                        slodom->setAttributeNS(shibspconstants::SHIB2SPCONFIG_NS, _policyId, e->getAttributeNS(nullptr, _policyId));

                    log.info("adding SingleLogoutService for Binding (%s) at (%s)", (*b)->getString("id").second, (*b)->getString("path").second);
                    boost::shared_ptr<Handler> handler(
                        conf.SingleLogoutServiceManager.newPlugin((*b)->getString("id").second, pair<const DOMElement*,const char*>(slodom, getId()))
                        );
                    m_handlers.push_back(handler);

                    // Insert into location map.
                    pair<bool,const char*> location = handler->getString("Location");
                    if (location.first && *location.second == '/')
                        m_handlerMap[location.second] = handler.get();
                    else if (location.first)
                        m_handlerMap[string("/") + location.second] = handler.get();
                }
                else {
                    log.error("missing id or path property on Binding element, check config for protocol (%s)", prot.get());
                }
            }

            if (protocols.count(prot.get()) == 0) {
                doArtifactResolution(pp, prot.get(), e, log);
                protocols.insert(prot.get());
            }
        }

        if (!initiator && bindings.empty()) {
            log.error("no Logout Initiator or Binding config for protocol (%s)", prot.get());
        }
    }

    // Attach default Location to Logout element.
    static const XMLCh _loc[] = { chForwardSlash, chLatin_L, chLatin_o, chLatin_g, chLatin_o, chLatin_u, chLatin_t, chNull };
    e->setAttributeNS(nullptr, Location, _loc);

    // Instantiate Chaining initiator around the SSO element.
    boost::shared_ptr<Handler> chain(
        conf.LogoutInitiatorManager.newPlugin(CHAINING_LOGOUT_INITIATOR, pair<const DOMElement*,const char*>(e, getId()))
        );
    m_handlers.push_back(chain);
    m_handlerMap["/Logout"] = chain.get();
}

void XMLApplication::doNameIDMgmt(const ProtocolProvider& pp, set<string>& protocols, DOMElement* e, Category& log)
{
    if (!e->hasChildNodes())
        return;
    DOMNamedNodeMap* nimprops = e->getAttributes();
    XMLSize_t nimpropslen = nimprops ? nimprops->getLength() : 0;

    SPConfig& conf = SPConfig::getConfig();

    // Tokenize the protocol list inside the element.
    XMLStringTokenizer prottokens(e->getTextContent());
    while (prottokens.hasMoreTokens()) {
        auto_ptr_char prot(prottokens.nextToken());

        // Look for incoming bindings.
        const vector<const PropertySet*>& bindings = pp.getBindings(prot.get(), "NameIDMgmt");
        if (!bindings.empty()) {
            log.info("auto-configuring NameIDMgmt endpoints for protocol (%s)", prot.get());
            pair<bool,const XMLCh*> idprop,pathprop;
            for (vector<const PropertySet*>::const_iterator b = bindings.begin(); b != bindings.end(); ++b) {
                idprop = (*b)->getXMLString("id");
                pathprop = (*b)->getXMLString("path");
                if (idprop.first && pathprop.first) {
                    DOMElement* nimdom = e->getOwnerDocument()->createElementNS(samlconstants::SAML20MD_NS, _ManageNameIDService);

                    // Copy in any attributes from the <NameIDMgmt> element so they can be accessed as properties in the NIM handler.
                    for (XMLSize_t p = 0; p < nimpropslen; ++p) {
                        DOMNode* nimprop = nimprops->item(p);
                        if (nimprop->getNodeType() == DOMNode::ATTRIBUTE_NODE) {
                            nimdom->setAttributeNS(
                                ((DOMAttr*)nimprop)->getNamespaceURI(),
                                ((DOMAttr*)nimprop)->getLocalName(),
                                ((DOMAttr*)nimprop)->getValue()
                                );
                        }
                    }

                    // Set necessary properties based on context.
                    nimdom->setAttributeNS(nullptr, Binding, idprop.second);
                    nimdom->setAttributeNS(nullptr, Location, pathprop.second);
                    if (e->hasAttributeNS(nullptr, _policyId))
                        nimdom->setAttributeNS(shibspconstants::SHIB2SPCONFIG_NS, _policyId, e->getAttributeNS(nullptr, _policyId));

                    log.info("adding ManageNameIDService for Binding (%s) at (%s)", (*b)->getString("id").second, (*b)->getString("path").second);
                    boost::shared_ptr<Handler> handler(
                        conf.ManageNameIDServiceManager.newPlugin((*b)->getString("id").second, pair<const DOMElement*,const char*>(nimdom, getId()))
                        );
                    m_handlers.push_back(handler);

                    // Insert into location map.
                    pair<bool,const char*> location = handler->getString("Location");
                    if (location.first && *location.second == '/')
                        m_handlerMap[location.second] = handler.get();
                    else if (location.first)
                        m_handlerMap[string("/") + location.second] = handler.get();
                }
                else {
                    log.error("missing id or path property on Binding element, check config for protocol (%s)", prot.get());
                }
            }

            if (protocols.count(prot.get()) == 0) {
                doArtifactResolution(pp, prot.get(), e, log);
                protocols.insert(prot.get());
            }
        }
        else {
            log.error("no NameIDMgmt Binding config for protocol (%s)", prot.get());
        }
    }
}

void XMLApplication::doArtifactResolution(const ProtocolProvider& pp, const char* protocol, DOMElement* e, Category& log)
{
    SPConfig& conf = SPConfig::getConfig();

    int index = 0; // track indexes globally across all protocols

    // Look for incoming bindings.
    const vector<const PropertySet*>& bindings = pp.getBindings(protocol, "ArtifactResolution");
    if (!bindings.empty()) {
        log.info("auto-configuring ArtifactResolution endpoints for protocol (%s)", protocol);
        pair<bool,const XMLCh*> idprop,pathprop;
        for (vector<const PropertySet*>::const_iterator b = bindings.begin(); b != bindings.end(); ++b, ++index) {
            idprop = (*b)->getXMLString("id");
            pathprop = (*b)->getXMLString("path");
            if (idprop.first && pathprop.first) {
                DOMElement* artdom = e->getOwnerDocument()->createElementNS(samlconstants::SAML20MD_NS, _ArtifactResolutionService);
                artdom->setAttributeNS(nullptr, Binding, idprop.second);
                artdom->setAttributeNS(nullptr, Location, pathprop.second);
                xstring indexbuf(1, chDigit_1 + (index % 10));
                if (index / 10)
                    indexbuf = (XMLCh)(chDigit_1 + (index / 10)) + indexbuf;
                artdom->setAttributeNS(nullptr, _index, indexbuf.c_str());

                log.info("adding ArtifactResolutionService for Binding (%s) at (%s)", (*b)->getString("id").second, (*b)->getString("path").second);
                boost::shared_ptr<Handler> handler(
                    conf.ArtifactResolutionServiceManager.newPlugin((*b)->getString("id").second, pair<const DOMElement*,const char*>(artdom, getId()))
                    );
                m_handlers.push_back(handler);

                if (!m_artifactResolutionDefault)
                    m_artifactResolutionDefault = handler.get();

                // Insert into location map.
                pair<bool,const char*> location = handler->getString("Location");
                if (location.first && *location.second == '/')
                    m_handlerMap[location.second] = handler.get();
                else if (location.first)
                    m_handlerMap[string("/") + location.second] = handler.get();
            }
            else {
                log.error("missing id or path property on Binding element, check config for protocol (%s)", protocol);
            }
        }
    }
}

#ifndef SHIBSP_LITE
void XMLApplication::doAttributePlugins(DOMElement* e, Category& log)
{
    SPConfig& conf = SPConfig::getConfig();

    m_attrExtractor.reset(
        doChainedPlugins(conf.AttributeExtractorManager, "AttributeExtractor", CHAINING_ATTRIBUTE_EXTRACTOR, _AttributeExtractor, e, log)
        );

    m_attrFilter.reset(
        doChainedPlugins(conf.AttributeFilterManager, "AttributeFilter", CHAINING_ATTRIBUTE_FILTER, _AttributeFilter, e, log, DUMMY_ATTRIBUTE_FILTER)
        );

    m_attrResolver.reset(
        doChainedPlugins(conf.AttributeResolverManager, "AttributeResolver", CHAINING_ATTRIBUTE_RESOLVER, _AttributeResolver, e, log)
        );

    if (m_unsetHeaders.empty()) {
        vector<string> unsetHeaders;
        if (m_attrExtractor) {
            Locker extlock(m_attrExtractor.get());
            m_attrExtractor->getAttributeIds(unsetHeaders);
        }
        else if (m_base && m_base->m_attrExtractor) {
            Locker extlock(m_base->m_attrExtractor.get());
            m_base->m_attrExtractor->getAttributeIds(unsetHeaders);
        }
        if (m_attrResolver) {
            Locker reslock(m_attrResolver.get());
            m_attrResolver->getAttributeIds(unsetHeaders);
        }
        else if (m_base && m_base->m_attrResolver) {
            Locker extlock(m_base->m_attrResolver.get());
            m_base->m_attrResolver->getAttributeIds(unsetHeaders);
        }
        if (!unsetHeaders.empty()) {
            string transformedprefix(m_attributePrefix.second);
            const char* pch;
            pair<bool,const char*> prefix = getString("metadataAttributePrefix");
            if (prefix.first) {
                pch = prefix.second;
                while (*pch) {
                    transformedprefix += (isalnum(*pch) ? toupper(*pch) : '_');
                    pch++;
                }
            }
            for (vector<string>::const_iterator hdr = unsetHeaders.begin(); hdr!=unsetHeaders.end(); ++hdr) {
                string transformed;
                pch = hdr->c_str();
                while (*pch) {
                    transformed += (isalnum(*pch) ? toupper(*pch) : '_');
                    pch++;
                }
                m_unsetHeaders.push_back(make_pair(m_attributePrefix.first + *hdr, m_attributePrefix.second + transformed));
                if (prefix.first)
                    m_unsetHeaders.push_back(make_pair(m_attributePrefix.first + prefix.second + *hdr, transformedprefix + transformed));
            }
        }
        m_unsetHeaders.push_back(make_pair(m_attributePrefix.first + "Shib-Application-ID", m_attributePrefix.second + "SHIB_APPLICATION_ID"));
    }
}
#endif

#ifdef SHIBSP_XERCESC_SHORT_ACCEPTNODE
short
#else
DOMNodeFilter::FilterAction
#endif
XMLApplication::acceptNode(const DOMNode* node) const
{
    const XMLCh* name=node->getLocalName();
    if (XMLString::equals(name,ApplicationOverride) ||
        XMLString::equals(name,_Audience) ||
        XMLString::equals(name,Notify) ||
        XMLString::equals(name,_Handler) ||
        XMLString::equals(name,_AssertionConsumerService) ||
        XMLString::equals(name,_ArtifactResolutionService) ||
        XMLString::equals(name,Logout) ||
        XMLString::equals(name,_LogoutInitiator) ||
        XMLString::equals(name,_ManageNameIDService) ||
        XMLString::equals(name,NameIDMgmt) ||
        XMLString::equals(name,_SessionInitiator) ||
        XMLString::equals(name,_SingleLogoutService) ||
        XMLString::equals(name,SSO) ||
        XMLString::equals(name,RelyingParty) ||
        XMLString::equals(name,_MetadataProvider) ||
        XMLString::equals(name,_TrustEngine) ||
        XMLString::equals(name,_CredentialResolver) ||
        XMLString::equals(name,_AttributeFilter) ||
        XMLString::equals(name,_AttributeExtractor) ||
        XMLString::equals(name,_AttributeResolver))
        return FILTER_REJECT;

    return FILTER_ACCEPT;
}

#ifndef SHIBSP_LITE

const PropertySet* XMLApplication::getRelyingParty(const EntityDescriptor* provider) const
{
    if (!provider)
        return this;

    // Check for exact match on name.
    map< xstring,boost::shared_ptr<PropertySet> >::const_iterator i = m_partyMap.find(provider->getEntityID());
    if (i != m_partyMap.end())
        return i->second.get();

    // Check for extensible matching.
    vector < pair< boost::shared_ptr<EntityMatcher>,boost::shared_ptr<PropertySet> > >::const_iterator j;
    for (j = m_partyVec.begin(); j != m_partyVec.end(); ++j) {
        if (j->first->matches(*provider))
            return j->second.get();
    }

    // Check for group match.
    const EntitiesDescriptor* group = dynamic_cast<const EntitiesDescriptor*>(provider->getParent());
    while (group) {
        if (group->getName()) {
            i = m_partyMap.find(group->getName());
            if (i != m_partyMap.end())
                return i->second.get();
        }
        group = dynamic_cast<const EntitiesDescriptor*>(group->getParent());
    }
    return this;
}

const PropertySet* XMLApplication::getRelyingParty(const XMLCh* entityID) const
{
    if (!entityID)
        return this;
    map< xstring,boost::shared_ptr<PropertySet> >::const_iterator i = m_partyMap.find(entityID);
    return (i != m_partyMap.end()) ? i->second.get() : this;
}

#endif

string XMLApplication::getNotificationURL(const char* resource, bool front, unsigned int index) const
{
    const vector<string>& locs = front ? m_frontLogout : m_backLogout;
    if (locs.empty())
        return m_base ? m_base->getNotificationURL(resource, front, index) : string();
    else if (index >= locs.size())
        return string();

#ifdef HAVE_STRCASECMP
    if (!resource || (strncasecmp(resource,"http://",7) && strncasecmp(resource,"https://",8)))
#else
    if (!resource || (strnicmp(resource,"http://",7) && strnicmp(resource,"https://",8)))
#endif
        throw ConfigurationException("Request URL was not absolute.");

    const char* handler = locs[index].c_str();

    // Should never happen...
    if (!handler || (*handler!='/' && strncmp(handler,"http:",5) && strncmp(handler,"https:",6)))
        throw ConfigurationException(
            "Invalid Location property ($1) in Notify element for Application ($2)",
            params(2, handler ? handler : "null", getId())
            );

    // The "Location" property can be in one of three formats:
    //
    // 1) a full URI:       http://host/foo/bar
    // 2) a hostless URI:   http:///foo/bar
    // 3) a relative path:  /foo/bar
    //
    // #  Protocol  Host        Path
    // 1  handler   handler     handler
    // 2  handler   resource    handler
    // 3  resource  resource    handler

    const char* path = nullptr;

    // Decide whether to use the handler or the resource for the "protocol"
    const char* prot;
    if (*handler != '/') {
        prot = handler;
    }
    else {
        prot = resource;
        path = handler;
    }

    // break apart the "protocol" string into protocol, host, and "the rest"
    const char* colon=strchr(prot,':');
    colon += 3;
    const char* slash=strchr(colon,'/');
    if (!path)
        path = slash;

    // Compute the actual protocol and store.
    string notifyURL(prot, colon-prot);

    // create the "host" from either the colon/slash or from the target string
    // If prot == handler then we're in either #1 or #2, else #3.
    // If slash == colon then we're in #2.
    if (prot != handler || slash == colon) {
        colon = strchr(resource, ':');
        colon += 3;      // Get past the ://
        slash = strchr(colon, '/');
    }
    string host(colon, (slash ? slash-colon : strlen(colon)));

    // Build the URL
    notifyURL += host + path;
    return notifyURL;
}

void XMLApplication::clearHeader(SPRequest& request, const char* rawname, const char* cginame) const
{
    if (!m_attributePrefix.first.empty()) {
        string temp = m_attributePrefix.first + rawname;
        string temp2 = m_attributePrefix.second + (cginame + 5);
        request.clearHeader(temp.c_str(), temp2.c_str());
    }
    else if (m_base) {
        m_base->clearHeader(request, rawname, cginame);
    }
    else {
        request.clearHeader(rawname, cginame);
    }
}

void XMLApplication::setHeader(SPRequest& request, const char* name, const char* value) const
{
    if (!m_attributePrefix.first.empty()) {
        string temp = m_attributePrefix.first + name;
        request.setHeader(temp.c_str(), value);
    }
    else if (m_base) {
        m_base->setHeader(request, name, value);
    }
    else {
        request.setHeader(name, value);
    }
}

string XMLApplication::getSecureHeader(const SPRequest& request, const char* name) const
{
    if (!m_attributePrefix.first.empty()) {
        string temp = m_attributePrefix.first + name;
        return request.getSecureHeader(temp.c_str());
    }
    else if (m_base) {
        return m_base->getSecureHeader(request,name);
    }
    else {
        return request.getSecureHeader(name);
    }
}

const SessionInitiator* XMLApplication::getDefaultSessionInitiator() const
{
    if (m_sessionInitDefault) return m_sessionInitDefault;
    return m_base ? m_base->getDefaultSessionInitiator() : nullptr;
}

const SessionInitiator* XMLApplication::getSessionInitiatorById(const char* id) const
{
    map<string,const SessionInitiator*>::const_iterator i = m_sessionInitMap.find(id);
    if (i != m_sessionInitMap.end()) return i->second;
    return m_base ? m_base->getSessionInitiatorById(id) : nullptr;
}

const Handler* XMLApplication::getDefaultAssertionConsumerService() const
{
    if (m_acsDefault) return m_acsDefault;
    return m_base ? m_base->getDefaultAssertionConsumerService() : nullptr;
}

const Handler* XMLApplication::getAssertionConsumerServiceByIndex(unsigned short index) const
{
    map<unsigned int,const Handler*>::const_iterator i = m_acsIndexMap.find(index);
    if (i != m_acsIndexMap.end()) return i->second;
    return m_base ? m_base->getAssertionConsumerServiceByIndex(index) : nullptr;
}

const Handler* XMLApplication::getAssertionConsumerServiceByProtocol(const XMLCh* protocol, const char* binding) const
{
    ACSProtocolMap::const_iterator i = m_acsProtocolMap.find(protocol);
    if (i != m_acsProtocolMap.end() && !i->second.empty()) {
        if (!binding || !*binding)
            return i->second.front();
        for (ACSProtocolMap::value_type::second_type::const_iterator j = i->second.begin(); j != i->second.end(); ++j) {
            if (!strcmp(binding, (*j)->getString("Binding").second))
                return *j;
        }
    }
    return m_base ? m_base->getAssertionConsumerServiceByProtocol(protocol, binding) : nullptr;
}

const vector<const Handler*>& XMLApplication::getAssertionConsumerServicesByBinding(const XMLCh* binding) const
{
    ACSBindingMap::const_iterator i = m_acsBindingMap.find(binding);
    if (i != m_acsBindingMap.end())
        return i->second;
    return m_base ? m_base->getAssertionConsumerServicesByBinding(binding) : g_noHandlers;
}

const Handler* XMLApplication::getHandler(const char* path) const
{
    string wrap(path);
    wrap = wrap.substr(0, wrap.find(';'));
    map<string,const Handler*>::const_iterator i = m_handlerMap.find(wrap.substr(0, wrap.find('?')));
    if (i != m_handlerMap.end())
        return i->second;
    return m_base ? m_base->getHandler(path) : nullptr;
}

void XMLApplication::getHandlers(vector<const Handler*>& handlers) const
{
    static void (vector<const Handler*>::* pb)(const Handler* const&) = &vector<const Handler*>::push_back;
    for_each(m_handlers.begin(), m_handlers.end(), boost::bind(pb, boost::ref(handlers), boost::bind(&boost::shared_ptr<Handler>::get, _1)));
    if (m_base) {
        for (map<string,const Handler*>::const_iterator h = m_base->m_handlerMap.begin(); h != m_base->m_handlerMap.end(); ++h) {
            if (m_handlerMap.count(h->first) == 0)
                handlers.push_back(h->second);
        }
    }
}

void XMLApplication::limitRedirect(const GenericRequest& request, const char* url) const
{
    if (!url || *url == '/')
        return;
    if (m_redirectLimit == REDIRECT_LIMIT_INHERIT)
        return m_base->limitRedirect(request, url);
    if (m_redirectLimit != REDIRECT_LIMIT_NONE) {
        vector<string> whitelist;
        if (m_redirectLimit == REDIRECT_LIMIT_EXACT || m_redirectLimit == REDIRECT_LIMIT_EXACT_WHITELIST) {
            // Scheme and hostname have to match.
            if (request.isDefaultPort()) {
                whitelist.push_back(string(request.getScheme()) + "://" + request.getHostname() + '/');
            }
            whitelist.push_back(string(request.getScheme()) + "://" + request.getHostname() + ':' + lexical_cast<string>(request.getPort()) + '/');
        }
        else if (m_redirectLimit == REDIRECT_LIMIT_HOST || m_redirectLimit == REDIRECT_LIMIT_HOST_WHITELIST) {
            // Allow any scheme or port.
            whitelist.push_back(string("https://") + request.getHostname() + '/');
            whitelist.push_back(string("http://") + request.getHostname() + '/');
            whitelist.push_back(string("https://") + request.getHostname() + ':');
            whitelist.push_back(string("http://") + request.getHostname() + ':');
        }

        static bool (*startsWithI)(const char*,const char*) = XMLString::startsWithI;
        if (!whitelist.empty() && find_if(whitelist.begin(), whitelist.end(),
                boost::bind(startsWithI, url, boost::bind(&string::c_str, _1))) != whitelist.end()) {
            return;
        }
        else if (!m_redirectWhitelist.empty() && find_if(m_redirectWhitelist.begin(), m_redirectWhitelist.end(),
                boost::bind(startsWithI, url, boost::bind(&string::c_str, _1))) != m_redirectWhitelist.end()) {
            return;
        }
        Category::getInstance(SHIBSP_LOGCAT".Application").warn("redirectLimit policy enforced, blocked redirect to (%s)", url);
        throw opensaml::SecurityPolicyException("Blocked unacceptable redirect location.");
    }
}

#ifdef SHIBSP_XERCESC_SHORT_ACCEPTNODE
short
#else
DOMNodeFilter::FilterAction
#endif
XMLConfigImpl::acceptNode(const DOMNode* node) const
{
    if (!XMLString::equals(node->getNamespaceURI(),shibspconstants::SHIB2SPCONFIG_NS))
        return FILTER_ACCEPT;
    const XMLCh* name=node->getLocalName();
    if (XMLString::equals(name,ApplicationDefaults) ||
        XMLString::equals(name,_ArtifactMap) ||
        XMLString::equals(name,_Extensions) ||
        XMLString::equals(name,Listener) ||
        XMLString::equals(name,_ProtocolProvider) ||
        XMLString::equals(name,_RequestMapper) ||
        XMLString::equals(name,_ReplayCache) ||
        XMLString::equals(name,SecurityPolicies) ||
        XMLString::equals(name,_SecurityPolicyProvider) ||
        XMLString::equals(name,_SessionCache) ||
        XMLString::equals(name,Site) ||
        XMLString::equals(name,_StorageService) ||
        XMLString::equals(name,TCPListener) ||
        XMLString::equals(name,TransportOption) ||
        XMLString::equals(name,UnixListener))
        return FILTER_REJECT;

    return FILTER_ACCEPT;
}

void XMLConfigImpl::doExtensions(const DOMElement* e, const char* label, Category& log)
{
    const DOMElement* exts = XMLHelper::getFirstChildElement(e, _Extensions);
    if (exts) {
        exts = XMLHelper::getFirstChildElement(exts, Library);
        while (exts) {
            string path(XMLHelper::getAttrString(exts, nullptr, _path));
            try {
                if (!path.empty()) {
                    if (!XMLToolingConfig::getConfig().load_library(path.c_str(), (void*)exts))
                        throw ConfigurationException("XMLToolingConfig::load_library failed.");
                    log.debug("loaded %s extension library (%s)", label, path.c_str());
                }
            }
            catch (std::exception& e) {
                if (XMLHelper::getAttrBool(exts, false, _fatal)) {
                    log.fatal("unable to load mandatory %s extension library %s: %s", label, path.c_str(), e.what());
                    throw;
                }
                else {
                    log.crit("unable to load optional %s extension library %s: %s", label, path.c_str(), e.what());
                }
            }
            exts = XMLHelper::getNextSiblingElement(exts, Library);
        }
    }
}

void XMLConfigImpl::doListener(const DOMElement* e, XMLConfig* conf, Category& log)
{
#ifdef WIN32
    string plugtype(TCP_LISTENER_SERVICE);
#else
    string plugtype(UNIX_LISTENER_SERVICE);
#endif
    DOMElement* child = XMLHelper::getFirstChildElement(e, UnixListener);
    if (child)
        plugtype = UNIX_LISTENER_SERVICE;
    else {
        child = XMLHelper::getFirstChildElement(e, TCPListener);
        if (child)
            plugtype = TCP_LISTENER_SERVICE;
        else {
            child = XMLHelper::getFirstChildElement(e, Listener);
            if (child) {
                auto_ptr_char type(child->getAttributeNS(nullptr, _type));
                if (type.get() && *type.get())
                    plugtype = type.get();
            }
        }
    }

    log.info("building ListenerService of type %s...", plugtype.c_str());
    conf->m_listener.reset(SPConfig::getConfig().ListenerServiceManager.newPlugin(plugtype.c_str(), child));
}

void XMLConfigImpl::doCaching(const DOMElement* e, XMLConfig* conf, Category& log)
{
    SPConfig& spConf = SPConfig::getConfig();
#ifndef SHIBSP_LITE
    SAMLConfig& samlConf = SAMLConfig::getConfig();
#endif

    DOMElement* child;
#ifndef SHIBSP_LITE
    if (spConf.isEnabled(SPConfig::OutOfProcess)) {
        XMLToolingConfig& xmlConf = XMLToolingConfig::getConfig();
        // First build any StorageServices.
        child = XMLHelper::getFirstChildElement(e, _StorageService);
        while (child) {
            string id(XMLHelper::getAttrString(child, nullptr, _id));
            string t(XMLHelper::getAttrString(child, nullptr, _type));
            if (!t.empty()) {
                try {
                    log.info("building StorageService (%s) of type %s...", id.c_str(), t.c_str());
                    conf->m_storage[id] = boost::shared_ptr<StorageService>(xmlConf.StorageServiceManager.newPlugin(t.c_str(), child));
                }
                catch (std::exception& ex) {
                    log.crit("failed to instantiate StorageService (%s): %s", id.c_str(), ex.what());
                }
            }
            child = XMLHelper::getNextSiblingElement(child, _StorageService);
        }

        if (conf->m_storage.empty()) {
            log.info("no StorageService plugin(s) installed, using (mem) in-memory instance");
            conf->m_storage["mem"] = boost::shared_ptr<StorageService>(xmlConf.StorageServiceManager.newPlugin(MEMORY_STORAGE_SERVICE, nullptr));
        }

        // Replay cache.
        StorageService* replaySS = nullptr;
        child = XMLHelper::getFirstChildElement(e, _ReplayCache);
        if (child) {
            string ssid(XMLHelper::getAttrString(child, nullptr, _StorageService));
            if (!ssid.empty()) {
                if (conf->m_storage.count(ssid)) {
                    log.info("building ReplayCache on top of StorageService (%s)...", ssid.c_str());
                    replaySS = conf->m_storage[ssid].get();
                }
                else {
                    log.error("unable to locate StorageService (%s), using arbitrary instance for ReplayCache", ssid.c_str());
                    replaySS = conf->m_storage.begin()->second.get();
                }
            }
            else {
                log.info("no StorageService specified for ReplayCache, using arbitrary instance");
                replaySS = conf->m_storage.begin()->second.get();
            }
        }
        else {
            log.info("no ReplayCache specified, using arbitrary StorageService instance");
            replaySS = conf->m_storage.begin()->second.get();
        }
        xmlConf.setReplayCache(new ReplayCache(replaySS));

        // ArtifactMap
        child = XMLHelper::getFirstChildElement(e, _ArtifactMap);
        if (child) {
            string ssid(XMLHelper::getAttrString(child, nullptr, _StorageService));
            if (!ssid.empty()) {
                if (conf->m_storage.count(ssid)) {
                    log.info("building ArtifactMap on top of StorageService (%s)...", ssid.c_str());
                    samlConf.setArtifactMap(new ArtifactMap(child, conf->m_storage[ssid].get()));
                }
                else {
                    log.error("unable to locate StorageService (%s), using in-memory ArtifactMap", ssid.c_str());
                    samlConf.setArtifactMap(new ArtifactMap(child));
                }
            }
            else {
                log.info("no StorageService specified, using in-memory ArtifactMap");
                samlConf.setArtifactMap(new ArtifactMap(child));
            }
        }
        else {
            log.info("no ArtifactMap specified, building in-memory ArtifactMap...");
            samlConf.setArtifactMap(new ArtifactMap(child));
        }
    }   // end of out of process caching components
#endif

    child = XMLHelper::getFirstChildElement(e, _SessionCache);
    if (child) {
        string t(XMLHelper::getAttrString(child, nullptr, _type));
        if (!t.empty()) {
            log.info("building SessionCache of type %s...", t.c_str());
            conf->m_sessionCache.reset(spConf.SessionCacheManager.newPlugin(t.c_str(), child));
        }
    }
    if (!conf->m_sessionCache) {
        log.info("no SessionCache specified, using StorageService-backed instance");
        conf->m_sessionCache.reset(spConf.SessionCacheManager.newPlugin(STORAGESERVICE_SESSION_CACHE, nullptr));
    }
}

XMLConfigImpl::XMLConfigImpl(const DOMElement* e, bool first, XMLConfig* outer, Category& log) : m_document(nullptr)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("XMLConfigImpl");
#endif
    SPConfig& conf=SPConfig::getConfig();
    XMLToolingConfig& xmlConf=XMLToolingConfig::getConfig();
    const DOMElement* SHAR=XMLHelper::getFirstChildElement(e, OutOfProcess);
    const DOMElement* SHIRE=XMLHelper::getFirstChildElement(e, InProcess);

    // Initialize logging manually in order to redirect log messages as soon as possible.
    // If no explicit config is supplied, we now assume the caller has done this, so that
    // setuid processes can potentially do this as root.
    if (conf.isEnabled(SPConfig::Logging)) {
        string logconf;
        if (conf.isEnabled(SPConfig::OutOfProcess))
            logconf = XMLHelper::getAttrString(SHAR, nullptr, logger);
        else if (conf.isEnabled(SPConfig::InProcess))
            logconf = XMLHelper::getAttrString(SHIRE, nullptr, logger);
        if (logconf.empty())
            logconf = XMLHelper::getAttrString(e, nullptr, logger);
        if (!logconf.empty()) {
            log.debug("loading new logging configuration from (%s), check log destination for status of configuration", logconf.c_str());
            if (!XMLToolingConfig::getConfig().log_config(logconf.c_str()))
                log.crit("failed to load new logging configuration from (%s)", logconf.c_str());
        }

#ifndef SHIBSP_LITE
        m_tranLog.reset(
            new TransactionLog(
                XMLHelper::getAttrString(SHAR, nullptr, tranLogFormat).c_str(),
                XMLHelper::getAttrString(SHAR, nullptr, tranLogFiller).c_str()
                )
            );
#endif
    }

    // Re-log library versions now that logging is set up.
    log.info("Shibboleth SP Version %s", PACKAGE_VERSION);
#ifndef SHIBSP_LITE
    log.info(
        "Library versions: %s %s, Xerces-C %s, XML-Security-C %s, XMLTooling-C %s, OpenSAML-C %s, Shibboleth %s",
# if defined(LOG4SHIB_VERSION)
    "log4shib", LOG4SHIB_VERSION,
# elif defined(LOG4CPP_VERSION)
    "log4cpp", LOG4CPP_VERSION,
# else
    "", "",
# endif
        XERCES_FULLVERSIONDOT, XSEC_FULLVERSIONDOT, gXMLToolingDotVersionStr, gOpenSAMLDotVersionStr, gShibSPDotVersionStr
        );
#else
    log.info(
        "Library versions: %s %s, Xerces-C %s, XMLTooling-C %s, Shibboleth %s",
# if defined(LOG4SHIB_VERSION)
    "log4shib", LOG4SHIB_VERSION,
# elif defined(LOG4CPP_VERSION)
    "log4cpp", LOG4CPP_VERSION,
# else
    "", "",
# endif
        XERCES_FULLVERSIONDOT, gXMLToolingDotVersionStr, gShibSPDotVersionStr
        );
#endif

    // First load any property sets.
    load(e, nullptr, this);

    DOMElement* child;

    // Much of the processing can only occur on the first instantiation.
    if (first) {
        // Set clock skew.
        pair<bool,unsigned int> skew=getUnsignedInt("clockSkew");
        if (skew.first)
            xmlConf.clock_skew_secs=min(skew.second,(60*60*24*7*28));

        pair<bool,const char*> unsafe = getString("unsafeChars");
        if (unsafe.first)
            TemplateEngine::unsafe_chars = unsafe.second;

        unsafe = getString("allowedSchemes");
        if (unsafe.first) {
            HTTPResponse::getAllowedSchemes().clear();
            string schemes(unsafe.second);
            split(HTTPResponse::getAllowedSchemes(), schemes, is_space(), algorithm::token_compress_on);
        }

        // Default language handling.
        pair<bool,bool> langFromClient = getBool("langFromClient");
        pair<bool,const XMLCh*> langPriority = getXMLString("langPriority");
        GenericRequest::setLangDefaults(!langFromClient.first || langFromClient.second, langPriority.second);

#ifndef SHIBSP_LITE
        langPriority = getXMLString("contactPriority");
        if (langPriority.first)
            SAMLConfig::getConfig().setContactPriority(langPriority.second);
#endif

        // Extensions
        doExtensions(e, "global", log);
        if (conf.isEnabled(SPConfig::OutOfProcess))
            doExtensions(SHAR, "out of process", log);

        if (conf.isEnabled(SPConfig::InProcess))
            doExtensions(SHIRE, "in process", log);

        // Instantiate the ListenerService and SessionCache objects.
        if (conf.isEnabled(SPConfig::Listener))
            doListener(e, outer, log);

#ifndef SHIBSP_LITE
        if (outer->m_listener && conf.isEnabled(SPConfig::OutOfProcess) && !conf.isEnabled(SPConfig::InProcess)) {
            outer->m_listener->regListener("set::RelayState", outer);
            outer->m_listener->regListener("get::RelayState", outer);
            outer->m_listener->regListener("set::PostData", outer);
            outer->m_listener->regListener("get::PostData", outer);
        }
#endif
        if (conf.isEnabled(SPConfig::Caching))
            doCaching(e, outer, log);
    } // end of first-time-only stuff

    // Back to the fully dynamic stuff...next up is the RequestMapper.
    if (conf.isEnabled(SPConfig::RequestMapping)) {
        if (child = XMLHelper::getFirstChildElement(e, _RequestMapper)) {
            string t(XMLHelper::getAttrString(child, nullptr, _type));
            if (!t.empty()) {
                log.info("building RequestMapper of type %s...", t.c_str());
                m_requestMapper.reset(conf.RequestMapperManager.newPlugin(t.c_str(), child));
            }
        }
        if (!m_requestMapper) {
            log.info("no RequestMapper specified, using 'Native' plugin with empty/default map");
            child = e->getOwnerDocument()->createElementNS(nullptr, _RequestMapper);
            DOMElement* mapperDummy = e->getOwnerDocument()->createElementNS(shibspconstants::SHIB2SPCONFIG_NS, RequestMap);
            mapperDummy->setAttributeNS(nullptr, applicationId, _default);
            child->appendChild(mapperDummy);
            m_requestMapper.reset(conf.RequestMapperManager.newPlugin(NATIVE_REQUEST_MAPPER, child));
        }
    }

#ifndef SHIBSP_LITE
    // Load security policies.
    if (child = XMLHelper::getLastChildElement(e, _SecurityPolicyProvider)) {
        string t(XMLHelper::getAttrString(child, nullptr, _type));
        if (!t.empty()) {
            log.info("building SecurityPolicyProvider of type %s...", t.c_str());
            m_policy.reset(conf.SecurityPolicyProviderManager.newPlugin(t.c_str(), child));
        }
        else {
            throw ConfigurationException("can't build SecurityPolicyProvider, no type specified");
        }
    }
    else if (child = XMLHelper::getLastChildElement(e, SecurityPolicies)) {
        // For backward compatibility, wrap in a plugin element.
        DOMElement* polwrapper = e->getOwnerDocument()->createElementNS(nullptr, _SecurityPolicyProvider);
        polwrapper->appendChild(child);
        log.warn("deprecated/legacy SecurityPolicy configuration, consider externalizing with <SecurityPolicyProvider>");
        m_policy.reset(conf.SecurityPolicyProviderManager.newPlugin(XML_SECURITYPOLICY_PROVIDER, polwrapper));
    }
    else {
        log.fatal("can't build SecurityPolicyProvider, missing conf:SecurityPolicyProvider element?");
        throw ConfigurationException("Can't build SecurityPolicyProvider, missing conf:SecurityPolicyProvider element?");
    }

    if (first) {
        if (!m_policy->getAlgorithmWhitelist().empty()) {
#ifdef SHIBSP_XMLSEC_WHITELISTING
            for (vector<xstring>::const_iterator white = m_policy->getAlgorithmWhitelist().begin();
                    white != m_policy->getAlgorithmWhitelist().end(); ++white) {
                XSECPlatformUtils::whitelistAlgorithm(white->c_str());
                auto_ptr_char whitelog(white->c_str());
                log.info("explicitly whitelisting security algorithm (%s)", whitelog.get());
            }
#else
            log.crit("XML-Security-C library prior to 1.6.0 does not support algorithm white/blacklists");
#endif
        }
        else if (!m_policy->getDefaultAlgorithmBlacklist().empty() || !m_policy->getAlgorithmBlacklist().empty()) {
#ifdef SHIBSP_XMLSEC_WHITELISTING
            for (vector<xstring>::const_iterator black = m_policy->getDefaultAlgorithmBlacklist().begin();
                    black != m_policy->getDefaultAlgorithmBlacklist().end(); ++black) {
                XSECPlatformUtils::blacklistAlgorithm(black->c_str());
                auto_ptr_char blacklog(black->c_str());
                log.info("automatically blacklisting security algorithm (%s)", blacklog.get());
            }
            for (vector<xstring>::const_iterator black = m_policy->getAlgorithmBlacklist().begin();
                    black != m_policy->getAlgorithmBlacklist().end(); ++black) {
                XSECPlatformUtils::blacklistAlgorithm(black->c_str());
                auto_ptr_char blacklog(black->c_str());
                log.info("explicitly blacklisting security algorithm (%s)", blacklog.get());
            }
#else
            log.crit("XML-Security-C library prior to 1.6.0 does not support algorithm white/blacklists");
#endif
        }
    }

    // Process TransportOption elements.
    child = XMLHelper::getLastChildElement(e, TransportOption);
    while (child) {
        if (child->hasChildNodes()) {
            string provider(XMLHelper::getAttrString(child, nullptr, _provider));
            string option(XMLHelper::getAttrString(child, nullptr, _option));
            auto_ptr_char value(child->getFirstChild()->getNodeValue());
            if (!provider.empty() && !option.empty() && value.get() && *value.get()) {
                m_transportOptions.push_back(make_tuple(provider, option, string(value.get())));
            }
        }
        child = XMLHelper::getPreviousSiblingElement(child, TransportOption);
    }
#endif

    scoped_ptr<ProtocolProvider> pp;
    if (conf.isEnabled(SPConfig::Handlers)) {
        if (child = XMLHelper::getLastChildElement(e, _ProtocolProvider)) {
            string t(XMLHelper::getAttrString(child, nullptr, _type));
            if (!t.empty()) {
                log.info("building ProtocolProvider of type %s...", t.c_str());
                pp.reset(conf.ProtocolProviderManager.newPlugin(t.c_str(), child));
            }
        }
    }
    Locker pplocker(pp.get());

    // Load the default application.
    child = XMLHelper::getLastChildElement(e, ApplicationDefaults);
    if (!child) {
        log.fatal("can't build default Application object, missing conf:ApplicationDefaults element?");
        throw ConfigurationException("can't build default Application object, missing conf:ApplicationDefaults element?");
    }
    boost::shared_ptr<XMLApplication> defapp(new XMLApplication(outer, pp.get(), child));
    m_appmap[defapp->getId()] = defapp;

    // Load any overrides.
    child = XMLHelper::getFirstChildElement(child, ApplicationOverride);
    while (child) {
        boost::shared_ptr<XMLApplication> iapp(new XMLApplication(outer, pp.get(), child, defapp.get()));
        if (m_appmap.count(iapp->getId()))
            log.crit("found conf:ApplicationOverride element with duplicate id attribute (%s), skipping it", iapp->getId());
        else
            m_appmap[iapp->getId()] = iapp;

        child = XMLHelper::getNextSiblingElement(child, ApplicationOverride);
    }

    // Check for extra AuthTypes to recognize.
    if (conf.isEnabled(SPConfig::InProcess)) {
        const PropertySet* inprocs = getPropertySet("InProcess");
        if (inprocs) {
            pair<bool,const char*> extraAuthTypes = inprocs->getString("extraAuthTypes");
            if (extraAuthTypes.first) {
                string types(extraAuthTypes.second);
                split(outer->m_authTypes, types, is_space(), algorithm::token_compress_on);
                outer->m_authTypes.insert("shibboleth");
            }
        }
    }
}

#ifndef SHIBSP_LITE
void XMLConfig::receive(DDF& in, ostream& out)
{
    if (!strcmp(in.name(), "get::RelayState")) {
        const char* id = in["id"].string();
        const char* key = in["key"].string();
        if (!id || !key)
            throw ListenerException("Required parameters missing for RelayState recovery.");

        string relayState;
        StorageService* storage = getStorageService(id);
        if (storage) {
            if (storage->readString("RelayState",key,&relayState)>0) {
                if (in["clear"].integer())
                    storage->deleteString("RelayState",key);
            }
            else if (storage->readText("RelayState",key,&relayState)>0) {
                if (in["clear"].integer())
                    storage->deleteText("RelayState",key);
            }
        }
        else {
            Category::getInstance(SHIBSP_LOGCAT".ServiceProvider").error(
                "Storage-backed RelayState with invalid StorageService ID (%s)", id
                );
        }

        // Repack for return to caller.
        DDF ret=DDF(nullptr).unsafe_string(relayState.c_str());
        DDFJanitor jret(ret);
        out << ret;
    }
    else if (!strcmp(in.name(), "set::RelayState")) {
        const char* id = in["id"].string();
        const char* value = in["value"].string();
        if (!id || !value)
            throw ListenerException("Required parameters missing for RelayState creation.");

        string rsKey;
        StorageService* storage = getStorageService(id);
        if (storage) {
            SAMLConfig::getConfig().generateRandomBytes(rsKey,32);
            rsKey = SAMLArtifact::toHex(rsKey);
            if (strlen(value) <= storage->getCapabilities().getStringSize())
                storage->createString("RelayState", rsKey.c_str(), value, time(nullptr) + 600);
            else
                storage->createText("RelayState", rsKey.c_str(), value, time(nullptr) + 600);
        }
        else {
            Category::getInstance(SHIBSP_LOGCAT".ServiceProvider").error(
                "Storage-backed RelayState with invalid StorageService ID (%s)", id
                );
        }

        // Repack for return to caller.
        DDF ret=DDF(nullptr).string(rsKey.c_str());
        DDFJanitor jret(ret);
        out << ret;
    }
    else if (!strcmp(in.name(), "get::PostData")) {
        const char* id = in["id"].string();
        const char* key = in["key"].string();
        if (!id || !key)
            throw ListenerException("Required parameters missing for PostData recovery.");

        string postData;
        StorageService* storage = getStorageService(id);
        if (storage) {
            if (storage->readText("PostData",key,&postData) > 0) {
                storage->deleteText("PostData",key);
            }
        }
        else {
            Category::getInstance(SHIBSP_LOGCAT".ServiceProvider").error(
                "Storage-backed PostData with invalid StorageService ID (%s)", id
                );
        }
        // If the data's empty, we'll send nothing back.
        // If not, we don't need to round trip it, just send back the serialized DDF list.
        if (postData.empty()) {
            DDF ret(nullptr);
            DDFJanitor jret(ret);
            out << ret;
        }
        else {
            out << postData;
        }
    }
    else if (!strcmp(in.name(), "set::PostData")) {
        const char* id = in["id"].string();
        if (!id || !in["parameters"].islist())
            throw ListenerException("Required parameters missing for PostData creation.");

        string rsKey;
        StorageService* storage = getStorageService(id);
        if (storage) {
            SAMLConfig::getConfig().generateRandomBytes(rsKey,32);
            rsKey = SAMLArtifact::toHex(rsKey);
            ostringstream params;
            params << in["parameters"];
            storage->createText("PostData", rsKey.c_str(), params.str().c_str(), time(nullptr) + 600);
        }
        else {
            Category::getInstance(SHIBSP_LOGCAT".ServiceProvider").error(
                "Storage-backed PostData with invalid StorageService ID (%s)", id
                );
        }

        // Repack for return to caller.
        DDF ret=DDF(nullptr).string(rsKey.c_str());
        DDFJanitor jret(ret);
        out << ret;
    }
}
#endif

pair<bool,DOMElement*> XMLConfig::background_load()
{
    // Load from source using base class.
    pair<bool,DOMElement*> raw = ReloadableXMLFile::load();

    // If we own it, wrap it.
    XercesJanitor<DOMDocument> docjanitor(raw.first ? raw.second->getOwnerDocument() : nullptr);

    scoped_ptr<XMLConfigImpl> impl(new XMLConfigImpl(raw.second, (m_impl==nullptr), this, m_log));

    // If we held the document, transfer it to the impl. If we didn't, it's a no-op.
    impl->setDocument(docjanitor.release());

    // Perform the swap inside a lock.
    if (m_lock)
        m_lock->wrlock();
    SharedLock locker(m_lock, false);
    m_impl.swap(impl);

    return make_pair(false,(DOMElement*)nullptr);
}

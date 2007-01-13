/*
 *  Copyright 2001-2005 Internet2
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

/*
 * shib-target.h -- top-level header file for the SHIB Common Target Library
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#ifndef SHIB_TARGET_H
#define SHIB_TARGET_H

// New headers
#include <shibsp/AbstractSPRequest.h>
#include <shibsp/Application.h>
#include <shibsp/ServiceProvider.h>
#include <shibsp/remoting/ListenerService.h>

// Old headers
#include <saml/saml.h>
#include <shib/shib.h>

#ifdef WIN32
# ifndef SHIBTARGET_EXPORTS
#  define SHIBTARGET_EXPORTS __declspec(dllimport)
# endif
# define SHIB_SCHEMAS "/opt/shibboleth-sp/share/xml/shibboleth"
# define SHIB_CONFIG "/opt/shibboleth-sp/etc/shibboleth/shibboleth.xml"
#else
# include <shib-target/shib-paths.h>
# define SHIBTARGET_EXPORTS
#endif

namespace shibtarget {
  
    // Abstract APIs for access to configuration information
    
    // Forward declaration
    class SHIBTARGET_EXPORTS ShibTarget;

    /**
     * Interface to a protocol handler
     * 
     * Protocol handlers perform system functions such as processing SAML protocol
     * messages to create and logout sessions or creating protocol requests.
     */
    struct SHIBTARGET_EXPORTS IHandler : public virtual saml::IPlugIn
    {
        IHandler() : m_props(NULL) {}
        virtual ~IHandler() {}
        virtual const shibsp::PropertySet* getProperties() const { return m_props; }
        virtual void setProperties(const shibsp::PropertySet* properties) { m_props=properties; }
        virtual std::pair<bool,long> run(ShibTarget* st, bool isHandler=true) const=0;
    private:
        const shibsp::PropertySet* m_props;
    };
    
    /**
     * Interface to Shibboleth Applications, which exposes most of the functionality
     * required to process web requests or security protocol messages for resources
     * associated with them.
     * 
     * Applications are implementation-specific, but generally correspond to collections
     * of resources related to one another in logical ways, such as a virtual host or
     * a Java servlet context. Most complex configuration data is associated with an
     * Application. Implementations should always expose an application named "default"
     * as a last resort.
     */
    struct SHIBTARGET_EXPORTS IApplication : public virtual shibsp::Application,
        public virtual shibboleth::ShibBrowserProfile::ITokenValidator
    {
        virtual saml::Iterator<saml::SAMLAttributeDesignator*> getAttributeDesignators() const=0;
        virtual saml::Iterator<shibboleth::IAAP*> getAAPProviders() const=0;
        virtual saml::Iterator<const XMLCh*> getAudiences() const=0;

        // caller is borrowing object, must use within scope of config lock
        virtual const saml::SAMLBrowserProfile* getBrowserProfile() const=0;
        virtual const saml::SAMLBinding* getBinding(const XMLCh* binding) const=0;

        // caller is given ownership of object, must use and delete within scope of config lock
        virtual saml::SAMLBrowserProfile::ArtifactMapper* getArtifactMapper() const=0;

        // general token validation based on conditions, signatures, etc.
        virtual void validateToken(
            saml::SAMLAssertion* token,
            time_t t=0,
            const opensaml::saml2md::RoleDescriptor* role=NULL,
            const xmltooling::TrustEngine* trust=NULL
            ) const=0;

        // Used to locate a default or designated session initiator for automatic sessions
        virtual const IHandler* getDefaultSessionInitiator() const=0;
        virtual const IHandler* getSessionInitiatorById(const char* id) const=0;
        
        // Used by session initiators to get endpoint to forward to IdP/WAYF
        virtual const IHandler* getDefaultAssertionConsumerService() const=0;
        virtual const IHandler* getAssertionConsumerServiceByIndex(unsigned short index) const=0;
        virtual saml::Iterator<const IHandler*> getAssertionConsumerServicesByBinding(const XMLCh* binding) const=0;
        
        // Used by dispatcher to locate the handler for a request
        virtual const IHandler* getHandler(const char* path) const=0;

        virtual ~IApplication() {}
    };

    /**
     * OpenSAML binding hook
     *
     * Instead of wrapping the binding to deal with mutual authentication, we
     * just use the HTTP hook functionality offered by OpenSAML. The hook will
     * register "itself" as a globalCtx pointer with the SAML binding and the caller
     * will declare and pass the embedded struct as callCtx for use by the hook.
     */
    class ShibHTTPHook : virtual public saml::SAMLSOAPHTTPBinding::HTTPHook
    {
    public:
        ShibHTTPHook(const xmltooling::TrustEngine* trust) : m_trust(trust) {}
        virtual ~ShibHTTPHook() {}
        
        // Only hook we need here is for outgoing connection to server.
        virtual bool outgoing(saml::HTTPClient* conn, void* globalCtx=NULL, void* callCtx=NULL);

        // Client declares a context object and pass as callCtx to send() method.
        class ShibHTTPHookCallContext {
        public:
            ShibHTTPHookCallContext(const shibsp::PropertySet* credUse, const opensaml::saml2md::RoleDescriptor* role)
                : m_credUse(credUse), m_role(role), m_hook(NULL), m_authenticated(false) {}
            const ShibHTTPHook* getHook() {return m_hook;}
            const shibsp::PropertySet* getCredentialUse() {return m_credUse;}
            const opensaml::saml2md::RoleDescriptor* getRoleDescriptor() {return m_role;}
            bool isAuthenticated() const {return m_authenticated;}
            void setAuthenticated() {m_authenticated=true;}
            
        private:
            const shibsp::PropertySet* m_credUse;
            const opensaml::saml2md::RoleDescriptor* m_role;
            ShibHTTPHook* m_hook;
            bool m_authenticated;
            friend class ShibHTTPHook;
        };
        
        const xmltooling::TrustEngine* getTrustEngine() const {return m_trust;}
    private:
        const xmltooling::TrustEngine* m_trust;
    };

    /**
     * Interface to a cached user session.
     * 
     * Cache entries provide implementations with access to the raw SAML information they
     * need to publish or provide access to the data for applications to use. All creation
     * or access to entries is through the ISessionCache interface, and callers must unlock
     * the entry when finished using it, rather than explicitly freeing them.
     */
    struct SHIBTARGET_EXPORTS ISessionCacheEntry : public virtual saml::ILockable
    {
        virtual const char* getClientAddress() const=0;
        virtual const char* getProviderId() const=0;
        virtual std::pair<const char*,const saml::SAMLSubject*> getSubject(bool xml=true, bool obj=false) const=0;
        virtual const char* getAuthnContext() const=0;
        virtual std::pair<const char*,const saml::SAMLResponse*> getTokens(bool xml=true, bool obj=false) const=0;
        virtual std::pair<const char*,const saml::SAMLResponse*> getFilteredTokens(bool xml=true, bool obj=false) const=0;
        virtual ~ISessionCacheEntry() {}
    };

    /**
     * Interface to a sink for session cache events.
     *
     * All caches support registration of a backing store that can be informed
     * of significant events in the lifecycle of a cache entry.
     */
    struct SHIBTARGET_EXPORTS ISessionCacheStore
    {
        virtual HRESULT onCreate(
            const char* key,
            const IApplication* application,
            const ISessionCacheEntry* entry,
            int majorVersion,
            int minorVersion,
            time_t created
            )=0;
        virtual HRESULT onRead(
            const char* key,
            std::string& applicationId,
            std::string& clientAddress,
            std::string& providerId,
            std::string& subject,
            std::string& authnContext,
            std::string& tokens,
            int& majorVersion,
            int& minorVersion,
            time_t& created,
            time_t& accessed
            )=0;
        virtual HRESULT onRead(const char* key, time_t& accessed)=0;
        virtual HRESULT onRead(const char* key, std::string& tokens)=0;
        virtual HRESULT onUpdate(const char* key, const char* tokens=NULL, time_t lastAccess=0)=0;
        virtual HRESULT onDelete(const char* key)=0;
        virtual ~ISessionCacheStore() {}
    };

    /**
     * Interface to the session cache.
     * 
     * The session cache abstracts a persistent (meaning across requests) cache of
     * instances of the ISessionCacheEntry interface. Creation of new entries and entry
     * lookup are confined to this interface to enable implementations to flexibly
     * remote and/or optimize calls by implementing custom versions of the
     * ISessionCacheEntry interface as required.
     */
    struct SHIBTARGET_EXPORTS ISessionCache : public virtual saml::IPlugIn
    {
        virtual std::string insert(
            const IApplication* application,
            const opensaml::saml2md::RoleDescriptor* source,
            const char* client_addr,
            const saml::SAMLSubject* subject,
            const char* authnContext,
            const saml::SAMLResponse* tokens
            )=0;
        virtual ISessionCacheEntry* find(
            const char* key, const IApplication* application, const char* client_addr
            )=0;
        virtual void remove(
            const char* key, const IApplication* application, const char* client_addr
            )=0;

        virtual bool setBackingStore(ISessionCacheStore* store)=0;
        virtual ~ISessionCache() {}
    };

    #define MEMORY_SESSIONCACHE "edu.internet2.middleware.shibboleth.sp.provider.MemorySessionCacheProvider"
    #define MYSQL_SESSIONCACHE  "edu.internet2.middleware.shibboleth.sp.provider.MySQLSessionCacheProvider"
    #define ODBC_SESSIONCACHE   "edu.internet2.middleware.shibboleth.sp.provider.ODBCSessionCacheProvider"

    #define MYSQL_REPLAYCACHE   "edu.internet2.middleware.shibboleth.sp.provider.MySQLReplayCacheProvider"
    #define ODBC_REPLAYCACHE    "edu.internet2.middleware.shibboleth.sp.provider.ODBCReplayCacheProvider"


    struct SHIBTARGET_EXPORTS IConfig : public virtual shibsp::ServiceProvider
    {
        virtual ISessionCache* getSessionCache() const=0;
        virtual saml::IReplayCache* getReplayCache() const=0;
        virtual ~IConfig() {}
    };

    class SHIBTARGET_EXPORTS ShibTargetConfig
    {
    public:
        ShibTargetConfig() : m_ini(NULL) {}
        virtual ~ShibTargetConfig() {}
        
        virtual bool init(const char* schemadir) = 0;
        virtual bool load(const char* config) = 0;
        virtual void shutdown() = 0;

        virtual IConfig* getINI() const {return m_ini;}

        static ShibTargetConfig& getConfig();

    protected:
        IConfig* m_ini;
    };

    class ShibTargetPriv;
    class SHIBTARGET_EXPORTS ShibTarget : public shibsp::AbstractSPRequest {
    public:
        ShibTarget(const IApplication* app);
        virtual ~ShibTarget(void);

        // These next two APIs are used to obtain the module-specific "OK"
        // and "Decline" results.  OK means "we believe that this request
        // should be accepted".  Declined means "we believe that this is
        // not a shibbolized request so we have no comment".

        virtual long returnDecline();
        virtual long returnOK();

        //
        // Note:  Subclasses need not implement anything below this line
        //

        // These functions implement the server-agnostic shibboleth engine
        // The web server modules implement a subclass and then call into 
        // these methods once they instantiate their request object.
        // 
        // Return value:
        //   these APIs will always return the result of sendPage(), sendRedirect(),
        //   returnDecline(), or returnOK() in the void* portion of the return code.
        //   Exactly what those values are is module- (subclass-) implementation
        //   specific.  The 'bool' part of the return value declares whether the
        //   void* is valid or not.  If the bool is true then the void* is valid.
        //   If the bool is false then the API did not call any callback, the void*
        //   is not valid, and the caller should continue processing (the API Call
        //   finished successfully).
        //
        //   The handleProfile argument declares whether doCheckAuthN() should
        //   automatically call doHandlePOST() when it encounters a request for
        //   the ShireURL;  if false it will call returnOK() instead.
        //
        std::pair<bool,long> doCheckAuthN(bool handler = false);
        std::pair<bool,long> doHandler();
        std::pair<bool,long> doCheckAuthZ();
        std::pair<bool,long> doExportAssertions(bool requireSession = true);

        // Basic request access in case any plugins need the info
        virtual const IConfig* getConfig() const;
        virtual const IApplication* getApplication() const;
        const char* getRequestURL() const {return m_url.c_str();}
        
    protected:
        ShibTarget();

        // Internal APIs

        // Initialize the request from the parsed URL
        // scheme == http, https, etc
        // hostname == server name
        // port == server port
        // uri == resource path
        // method == GET, POST, etc.
        void init(
            const char* scheme,
            const char* hostname,
            int port,
            const char* uri,
            const char* content_type,
            const char* remote_addr,
            const char* method
            );

        std::string m_url, m_method, m_scheme, m_hostname, m_uri, m_content_type, m_remote_addr;
        int m_port;

    private:
        mutable ShibTargetPriv* m_priv;
        friend class ShibTargetPriv;
    };

}

#endif /* SHIB_TARGET_H */

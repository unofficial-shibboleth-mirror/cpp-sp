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

#include <saml/saml.h>
#include <shib/shib.h>
#include <shib/shib-threads.h>

#ifdef WIN32
# ifndef SHIBTARGET_EXPORTS
#  define SHIBTARGET_EXPORTS __declspec(dllimport)
# endif
# define SHIB_SCHEMAS "/opt/shibboleth-sp/share/xml/shibboleth"
# define SHIB_CONFIG "/opt/shibboleth-sp/etc/shibboleth/shibboleth.xml"
# include <winsock.h>
#else
# include <shib-target/shib-paths.h>
# define SHIBTARGET_EXPORTS
#endif


namespace shibtarget {
  
    DECLARE_SAML_EXCEPTION(SHIBTARGET_EXPORTS,ListenerException,SAMLException);
    DECLARE_SAML_EXCEPTION(SHIBTARGET_EXPORTS,ConfigurationException,SAMLException);

    enum ShibProfile {
      PROFILE_UNSPECIFIED = 0,
      SAML10_POST = 1,
      SAML10_ARTIFACT = 2,
      SAML11_POST = 4,
      SAML11_ARTIFACT = 8,
      SAML20_SSO = 16
    };

    // Abstract APIs for access to configuration information
    
    struct SHIBTARGET_EXPORTS IPropertySet
    {
        virtual std::pair<bool,bool> getBool(const char* name, const char* ns=NULL) const=0;
        virtual std::pair<bool,const char*> getString(const char* name, const char* ns=NULL) const=0;
        virtual std::pair<bool,const XMLCh*> getXMLString(const char* name, const char* ns=NULL) const=0;
        virtual std::pair<bool,unsigned int> getUnsignedInt(const char* name, const char* ns=NULL) const=0;
        virtual std::pair<bool,int> getInt(const char* name, const char* ns=NULL) const=0;
        virtual const IPropertySet* getPropertySet(const char* name, const char* ns="urn:mace:shibboleth:target:config:1.0") const=0;
        virtual const DOMElement* getElement() const=0;
        virtual ~IPropertySet() {}
    };

    struct SHIBTARGET_EXPORTS IApplication : public virtual IPropertySet
    {
        virtual const char* getId() const=0;
        virtual const char* getHash() const=0;
        
        virtual saml::Iterator<saml::SAMLAttributeDesignator*> getAttributeDesignators() const=0;
        virtual saml::Iterator<shibboleth::IAAP*> getAAPProviders() const=0;
        virtual saml::Iterator<shibboleth::IMetadata*> getMetadataProviders() const=0;
        virtual saml::Iterator<shibboleth::ITrust*> getTrustProviders() const=0;
        virtual saml::Iterator<const XMLCh*> getAudiences() const=0;
        virtual const IPropertySet* getCredentialUse(const shibboleth::IEntityDescriptor* provider) const=0;

        // caller is borrowing object, must use within scope of config lock
        virtual const saml::SAMLBrowserProfile* getBrowserProfile() const=0;
        virtual const saml::SAMLBinding* getBinding(const XMLCh* binding) const=0;

        // caller is given ownership of object, must use and delete within scope of config lock
        virtual saml::SAMLBrowserProfile::ArtifactMapper* getArtifactMapper() const=0;

        // Used to locate a default or designated session initiator for automatic sessions
        virtual const IPropertySet* getDefaultSessionInitiator() const=0;
        virtual const IPropertySet* getSessionInitiatorById(const char* id) const=0;
        
        // Used by session initiators to get endpoint to forward to IdP/WAYF
        virtual const IPropertySet* getDefaultAssertionConsumerService() const=0;
        virtual const IPropertySet* getAssertionConsumerServiceByIndex(unsigned short index) const=0;
        
        // Used by dispatcher to locate the handler configuration for a Shibboleth request
        virtual const IPropertySet* getHandlerConfig(const char* path) const=0;

        virtual ~IApplication() {}
    };

    // Instead of wrapping the binding to deal with mutual authentication, we
    // just use the HTTP hook functionality offered by OpenSAML. The hook will
    // register "itself" as a globalCtx pointer with the SAML binding and the caller
    // will declare and pass the embedded struct as callCtx for use by the hook.
    class ShibHTTPHook : virtual public saml::SAMLSOAPHTTPBinding::HTTPHook
    {
    public:
        ShibHTTPHook(const saml::Iterator<shibboleth::ITrust*>& trusts, const saml::Iterator<shibboleth::ICredentials*>& creds)
            : m_trusts(trusts), m_creds(creds) {}
        virtual ~ShibHTTPHook() {}
        
        // Only hook we need here is for outgoing connection to server.
        virtual bool outgoing(saml::HTTPClient* conn, void* globalCtx=NULL, void* callCtx=NULL);

        // Client declares a context object and pass as callCtx to send() method.
        class ShibHTTPHookCallContext {
        public:
            ShibHTTPHookCallContext(const IPropertySet* credUse, const shibboleth::IRoleDescriptor* role)
                : m_credUse(credUse), m_role(role), m_hook(NULL), m_authenticated(false) {}
            const ShibHTTPHook* getHook() {return m_hook;}
            const IPropertySet* getCredentialUse() {return m_credUse;}
            const shibboleth::IRoleDescriptor* getRoleDescriptor() {return m_role;}
            bool isAuthenticated() const {return m_authenticated;}
            void setAuthenticated() {m_authenticated=true;}
            
        private:
            const IPropertySet* m_credUse;
            const shibboleth::IRoleDescriptor* m_role;
            ShibHTTPHook* m_hook;
            bool m_authenticated;
            friend class ShibHTTPHook;
        };
        
        const saml::Iterator<shibboleth::ITrust*>& getTrustProviders() const {return m_trusts;}
        const saml::Iterator<shibboleth::ICredentials*>& getCredentialProviders() const {return m_creds;}
    private:
        saml::Iterator<shibboleth::ITrust*> m_trusts;
        saml::Iterator<shibboleth::ICredentials*> m_creds;
    };

    struct SHIBTARGET_EXPORTS ISessionCacheEntry : public virtual saml::ILockable
    {
        virtual bool isValid(time_t lifetime, time_t timeout) const=0;
        virtual const char* getClientAddress() const=0;
        virtual ShibProfile getProfile() const=0;
        virtual const char* getProviderId() const=0;
        virtual const char* getAuthnStatement() const=0;
        struct SHIBTARGET_EXPORTS CachedResponse {
            CachedResponse(const char* unfiltered, const char* filtered) {
                this->unfiltered=unfiltered;
                this->filtered=filtered;
            }
            const char* unfiltered;
            const char* filtered;
        };
        virtual CachedResponse getResponse()=0;
        virtual ~ISessionCacheEntry() {}
    };

    struct SHIBTARGET_EXPORTS ISessionCache : public virtual saml::IPlugIn
    {
        virtual void thread_init()=0;
        virtual void thread_end()=0;
        virtual std::string generateKey() const=0;
        virtual void insert(
            const char* key,
            const IApplication* application,
            const char* client_addr,
            ShibProfile profile,
            const char* providerId,
            const saml::SAMLAuthenticationStatement* s,
            // use this to feed any pushed attributes inside a SAML response
            saml::SAMLResponse* r=NULL, // (object may be modified but is still owned by caller)
            const shibboleth::IRoleDescriptor* source=NULL, // source of pushed attributes
            time_t created=0,
            time_t accessed=0
            )=0;
        virtual ISessionCacheEntry* find(const char* key, const IApplication* application)=0;
        virtual void remove(const char* key)=0;
        virtual ~ISessionCache() {}
    };

    struct SHIBTARGET_EXPORTS IListener : public virtual saml::IPlugIn
    {
        // The socket APIs should really be somewhere else, but compatibility
        // with older configuration files dictates that the Listener handles
        // both client and server socket handling. We can fix this for 2.0...?
#ifdef WIN32
        typedef SOCKET ShibSocket;
#else
        typedef int ShibSocket;
#endif
        virtual bool create(ShibSocket& s) const=0;
        virtual bool bind(ShibSocket& s, bool force=false) const=0;
        virtual bool connect(ShibSocket& s) const=0;
        virtual bool close(ShibSocket& s) const=0;
        virtual bool accept(ShibSocket& listener, ShibSocket& s) const=0;

        // The "real" Listener API abstracts the primitive operations that make up
        // the meat of the SP's job. Right now, that's session create/read/delete.
        virtual void sessionNew(
            const IApplication* application,
            int supported_profiles,
            const char* recipient,
            const char* packet,
            const char* ip,
            std::string& target,
            std::string& cookie,
            std::string& provider_id
            ) const=0;
    
        virtual void sessionGet(
            const IApplication* application,
            const char* cookie,
            const char* ip,
            ISessionCacheEntry** pentry
            ) const=0;
    
        virtual void sessionEnd(
            const IApplication* application,
            const char* cookie
            ) const=0;
            
        virtual void ping(int& i) const=0;
        
        virtual ~IListener() {}
    };

    class SHIBTARGET_EXPORTS ShibTarget;

    struct SHIBTARGET_EXPORTS IAccessControl : public virtual saml::ILockable, public virtual saml::IPlugIn
    {
        virtual bool authorized(ShibTarget* st, ISessionCacheEntry* entry) const=0;
        virtual ~IAccessControl() {}
    };

    struct SHIBTARGET_EXPORTS IRequestMapper : public virtual saml::ILockable, public virtual saml::IPlugIn
    {
        typedef std::pair<const IPropertySet*,IAccessControl*> Settings;
        virtual Settings getSettings(ShibTarget* st) const=0;
        virtual ~IRequestMapper() {}
    };
    
    struct SHIBTARGET_EXPORTS IHandler : public virtual saml::IPlugIn
    {
        virtual std::pair<bool,void*> run(ShibTarget* st, const IPropertySet* config, bool isHandler=true)=0;
        virtual ~IHandler() {}
    };
    
    struct SHIBTARGET_EXPORTS IConfig : public virtual saml::ILockable, public virtual IPropertySet, public virtual saml::IPlugIn
    {
        virtual const IListener* getListener() const=0;
        virtual ISessionCache* getSessionCache() const=0;
        virtual saml::IReplayCache* getReplayCache() const=0;
        virtual IRequestMapper* getRequestMapper() const=0;
        virtual const IApplication* getApplication(const char* applicationId) const=0;
        virtual saml::Iterator<shibboleth::ICredentials*> getCredentialsProviders() const=0;
        virtual ~IConfig() {}
    };

    class SHIBTARGET_EXPORTS ShibTargetConfig
    {
    public:
        ShibTargetConfig() : m_ini(NULL), m_features(0) {}
        virtual ~ShibTargetConfig() {}
        
        virtual bool init(const char* schemadir) = 0;
        virtual bool load(const char* config) = 0;
        virtual void shutdown() = 0;

        enum components_t {
            Listener = 1,
            Caching = 2,
            Metadata = 4,
            Trust = 8,
            Credentials = 16,
            AAP = 32,
            RequestMapper = 64,
            GlobalExtensions = 128,
            LocalExtensions = 256,
            Logging = 512
        };
        void setFeatures(long enabled) {m_features = enabled;}
        bool isEnabled(components_t feature) {return (m_features & feature)>0;}
        virtual IConfig* getINI() const {return m_ini;}

        static ShibTargetConfig& getConfig();

    protected:
        IConfig* m_ini;
        
    private:
        unsigned long m_features;
    };

  class ShibTargetPriv;
  class SHIBTARGET_EXPORTS ShibTarget {
  public:
    ShibTarget(const IApplication *app);
    virtual ~ShibTarget(void);

    // These are defined here so the subclass does not need to specifically
    // depend on log4cpp.  We could use log4cpp::Priority::PriorityLevel
    // but this is just as easy, IMHO.  It's just a case statement in the
    // implementation to handle the event level.
    enum ShibLogLevel {
      LogLevelDebug,
      LogLevelInfo,
      LogLevelWarn,
      LogLevelError
    };

    //
    // Note: subclasses MUST implement ALL of these virtual methods
    //
    
    // Send a message to the Webserver log
    virtual void log(ShibLogLevel level, const std::string &msg)=0;

    void log(ShibLogLevel level, const char *msg) {
      std::string s = msg;
      log(level, s);
    }

    // Get/Set a cookie for this request
    virtual std::string getCookies() const=0;
    virtual void setCookie(const std::string &name, const std::string &value)=0;
    virtual const char* getCookie(const std::string& name) const;
    void setCookie(const char *name, const char *value) {
      std::string ns = name;
      std::string vs = value;
      setCookie(ns, vs);
    }
    void setCookie(const char *name, const std::string &value) {
      std::string ns = name;
      setCookie(ns, value);
    }


    // Get the request's GET arguments or POST data from the server
    virtual std::string getArgs(void)=0;
    virtual std::string getPostData(void)=0;

    // Clear a header, set a header
    // These APIs are used for exporting the Assertions into the
    // Headers.  It will clear some well-known headers first to make
    // sure none remain.  Then it will process the set of assertions
    // and export them via setHeader().
    virtual void clearHeader(const std::string &name)=0;
    virtual void setHeader(const std::string &name, const std::string &value)=0;
    virtual std::string getHeader(const std::string &name)=0;
    virtual void setRemoteUser(const std::string &user)=0;
    virtual std::string getRemoteUser(void)=0;

    void clearHeader(const char *n) {
      std::string s = n;
      clearHeader(s);
    }
    void setHeader(const char *n, const char *v) {
      std::string ns = n;
      std::string vs = v;
      setHeader(ns, vs);
    }
    void setHeader(const std::string &n, const char *v) {
      std::string vs = v;
      setHeader(n, vs);
    }
    void setHeader(const char *n, const std::string &v) {
      std::string ns = n;
      setHeader(ns, v);
    }
    std::string getHeader(const char *n) {
      std::string s = n;
      return getHeader(s);
    }
    void setRemoteUser(const char *n) {
      std::string s = n;
      setRemoteUser(s);
    }

    // We're done.  Finish up.  Send specific result content or a redirect.
    // If there are no headers supplied assume the content-type is text/html
    typedef std::pair<std::string, std::string> header_t;
    virtual void* sendPage(
        const std::string& msg,
        int code = 200,
        const std::string& content_type = "text/html",
        const saml::Iterator<header_t>& headers = EMPTY(header_t)
        )=0;
    void* sendPage(const char *msg) {
      std::string m = msg;
      return sendPage(m);
    }
    virtual void* sendRedirect(const std::string& url)=0;
    
    // These next two APIs are used to obtain the module-specific "OK"
    // and "Decline" results.  OK means "we believe that this request
    // should be accepted".  Declined means "we believe that this is
    // not a shibbolized request so we have no comment".

    virtual void* returnDecline(void);
    virtual void* returnOK(void);

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
    std::pair<bool,void*> doCheckAuthN(bool handler = false);
    std::pair<bool,void*> doHandler();
    std::pair<bool,void*> doCheckAuthZ();
    std::pair<bool,void*> doExportAssertions(bool requireSession = true);

    // Basic request access in case any plugins need the info
    virtual const IConfig* getConfig() const;
    virtual const IApplication* getApplication() const;
    const char* getRequestMethod() const {return m_method.c_str();}
    const char* getProtocol() const {return m_protocol.c_str();}
    const char* getHostname() const {return m_hostname.c_str();}
    int getPort() const {return m_port;}
    const char* getRequestURI() const {return m_uri.c_str();}
    const char* getContentType() const {return m_content_type.c_str();}
    const char* getRemoteAddr() const {return m_remote_addr.c_str();}
    const char* getRequestURL() const {return m_url.c_str();}
    
    // Advanced methods useful to profile handlers implemented outside core
    
    // Get per-application session and state cookie name and properties
    virtual std::pair<std::string,const char*> getCookieNameProps(const char* prefix) const;
    
    // Determine the effective handler URL based on the resource URL
    virtual std::string getHandlerURL(const char* resource) const;

  protected:
    ShibTarget();

    // Internal APIs

    // Initialize the request from the parsed URL
    // protocol == http, https, etc
    // hostname == server name
    // port == server port
    // uri == resource path
    // method == GET, POST, etc.
    void init(
        const char* protocol,
        const char* hostname,
        int port,
        const char* uri,
        const char* content_type,
        const char* remote_addr,
        const char* method
        );

    std::string m_url, m_method, m_protocol, m_hostname, m_uri, m_content_type, m_remote_addr;
    int m_port;

  private:
    mutable ShibTargetPriv* m_priv;
    friend class ShibTargetPriv;
  };

    struct SHIBTARGET_EXPORTS XML
    {
        static const XMLCh SHIBTARGET_NS[];
        static const XMLCh SHIBTARGET_SCHEMA_ID[];
        static const XMLCh SAML2ASSERT_NS[];
        static const XMLCh SAML2ASSERT_SCHEMA_ID[];
        static const XMLCh SAML2META_NS[];
        static const XMLCh SAML2META_SCHEMA_ID[];
        static const XMLCh XMLENC_NS[];
        static const XMLCh XMLENC_SCHEMA_ID[];
    
        // Session cache implementations
        static const char MemorySessionCacheType[];
        static const char MySQLSessionCacheType[];
        
        // Replay cache implementations
        static const char MySQLReplayCacheType[];
        
        // Request mapping/settings implementations
        static const char XMLRequestMapType[];      // portable XML-based map
        static const char NativeRequestMapType[];   // Native web server command override of XML-based map
        static const char LegacyRequestMapType[];   // older designation of XML map, hijacked by web server
        
        // Access control implementations
        static const char htAccessControlType[];    // Apache-specific .htaccess authz module
        static const char XMLAccessControlType[];   // Proprietary but portable XML authz syntax

        // Listener implementations
        static const char TCPListenerType[];        // ONC RPC via TCP socket
        static const char UnixListenerType[];       // ONC RPC via domain socker
        static const char MemoryListenerType[];     // "faked" in-process marshalling
    
        struct SHIBTARGET_EXPORTS Literals
        {
            static const XMLCh AAPProvider[];
            static const XMLCh AccessControl[];
            static const XMLCh AccessControlProvider[];
            static const XMLCh acl[];
            static const XMLCh AND[];
            static const XMLCh applicationId[];
            static const XMLCh Application[];
            static const XMLCh Applications[];
            static const XMLCh AssertionConsumerService[];
            static const XMLCh AttributeFactory[];
            static const XMLCh config[];
            static const XMLCh CredentialsProvider[];
            static const XMLCh CredentialUse[];
            static const XMLCh DiagnosticService[];
            static const XMLCh echo[];
            static const XMLCh Extensions[];
            static const XMLCh fatal[];
            static const XMLCh FederationProvider[];
            static const XMLCh Global[];
            static const XMLCh Host[];
            static const XMLCh htaccess[];
            static const XMLCh Implementation[];
            static const XMLCh index[];
            static const XMLCh isDefault[];
            static const XMLCh Library[];
            static const XMLCh Listener[];
            static const XMLCh Local[];
            static const XMLCh log[];
            static const XMLCh logger[];
            static const XMLCh MemorySessionCache[];
            static const XMLCh MetadataProvider[];
            static const XMLCh MySQLReplayCache[];
            static const XMLCh MySQLSessionCache[];
            static const XMLCh name[];
            static const XMLCh Name[];
            static const XMLCh NOT[];
            static const XMLCh OR[];
            static const XMLCh Path[];
            static const XMLCh path[];
            static const XMLCh RelyingParty[];
            static const XMLCh ReplayCache[];
            static const XMLCh RequestMap[];
            static const XMLCh RequestMapProvider[];
            static const XMLCh require[];
            static const XMLCh Rule[];
            static const XMLCh SessionCache[];
            static const XMLCh SessionInitiator[];
            static const XMLCh SHAR[];
            static const XMLCh ShibbolethTargetConfig[];
            static const XMLCh SHIRE[];
            static const XMLCh Signing[];
            static const XMLCh SingleLogoutService[];
            static const XMLCh SPConfig[];
            static const XMLCh TCPListener[];
            static const XMLCh TLS[];
            static const XMLCh TrustProvider[];
            static const XMLCh type[];
            static const XMLCh UnixListener[];
        };
    };
}

#endif /* SHIB_TARGET_H */

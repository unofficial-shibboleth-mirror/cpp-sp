/*
 * The Shibboleth License, Version 1.
 * Copyright (c) 2002
 * University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution, if any, must include
 * the following acknowledgment: "This product includes software developed by
 * the University Corporation for Advanced Internet Development
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement
 * may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear.
 *
 * Neither the name of Shibboleth nor the names of its contributors, nor
 * Internet2, nor the University Corporation for Advanced Internet Development,
 * Inc., nor UCAID may be used to endorse or promote products derived from this
 * software without specific prior written permission. For written permission,
 * please contact shibboleth@shibboleth.org
 *
 * Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor
 * may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
# define SHIB_SCHEMAS "/opt/shibboleth/share/xml/shibboleth"
# define SHIB_CONFIG "/opt/shibboleth/etc/shibboleth/shibboleth.xml"
#else
# include <shib-target/shib-paths.h>
# define SHIBTARGET_EXPORTS
#endif

#include <shib-target/shibrpc.h>

namespace shibtarget {
  
  //******************************************************************************
  // You probably don't care about much below this line
  // unless you are using the lower-layer APIs provided by
  // the shib target library.  Go to the end of the file to
  // find the ShibTarget class -- you probably wnat to use that.
  //

  class SHIBTARGET_EXPORTS ShibTargetException : public std::exception
  {
  public:
    explicit ShibTargetException() : m_code(SHIBRPC_OK) {}
    explicit ShibTargetException(ShibRpcStatus code, const char* msg, const shibboleth::IEntityDescriptor* provider);
    explicit ShibTargetException(ShibRpcStatus code, const char* msg, const shibboleth::IRoleDescriptor* role=NULL);
    
    virtual ~ShibTargetException() throw () {}
    virtual ShibRpcStatus which() const throw () { return m_code; }
    virtual const char* what() const throw () { return m_msg.c_str(); }
    virtual const char* syswho() const throw() { return m_providerId.c_str(); }
    virtual const char* where() const throw () { return m_errorURL.c_str(); }
    virtual const char* who() const throw () { return m_contact.c_str(); }
    virtual const char* how() const throw () { return m_email.c_str(); }

  private:
    ShibRpcStatus m_code;
    std::string m_msg;
    std::string m_providerId;
    std::string m_errorURL;
    std::string m_contact;
    std::string m_email;
  };

  class RPCErrorPriv;
  class SHIBTARGET_EXPORTS RPCError
  {
  public:
    RPCError();
    RPCError(ShibRpcError* e);
    RPCError(int s, const char* st);
    RPCError(ShibTargetException &exp);
    ~RPCError();

    bool isError();
    bool isRetryable();

    // Return a set of strings that correspond to the error properties
    const char* getType();
    const char* getText();
    const char* getDesc();
    const char* getProviderId();
    const char* getErrorURL();
    const char* getContactName();
    const char* getContactEmail();
    int getCode();

  private:
    RPCErrorPriv* m_priv;
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

    struct SHIBTARGET_EXPORTS IListener : public virtual shibboleth::IPlugIn
    {
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
        virtual CLIENT* getClientHandle(ShibSocket& s, u_long program, u_long version) const=0;
        virtual ~IListener() {}
    };

    struct SHIBTARGET_EXPORTS IAccessControl : public virtual shibboleth::ILockable, public virtual shibboleth::IPlugIn
    {
        virtual bool authorized(
            const saml::SAMLAuthenticationStatement& authn, const saml::Iterator<saml::SAMLAssertion*>& attrs
            ) const=0;
        virtual ~IAccessControl() {}
    };

    struct SHIBTARGET_EXPORTS IRequestMapper : public virtual shibboleth::ILockable, public virtual shibboleth::IPlugIn
    {
        typedef std::pair<const IPropertySet*,IAccessControl*> Settings;
        virtual Settings getSettingsFromURL(const char* url) const=0;
        virtual Settings getSettingsFromParsedURL(
            const char* scheme, const char* hostname, unsigned int port, const char* path=NULL
            ) const=0;
        virtual ~IRequestMapper() {}
    };
    
    struct SHIBTARGET_EXPORTS IApplication : public virtual IPropertySet
    {
        virtual const char* getId() const=0;
        virtual saml::Iterator<saml::SAMLAttributeDesignator*> getAttributeDesignators() const=0;
        virtual saml::Iterator<shibboleth::IAAP*> getAAPProviders() const=0;
        virtual saml::Iterator<shibboleth::IMetadata*> getMetadataProviders() const=0;
        virtual saml::Iterator<shibboleth::ITrust*> getTrustProviders() const=0;
        virtual saml::Iterator<shibboleth::IRevocation*> getRevocationProviders() const=0;
        virtual saml::Iterator<const XMLCh*> getAudiences() const=0;
        virtual const char* getTLSCred(const shibboleth::IEntityDescriptor* provider) const=0;
        virtual const char* getSigningCred(const shibboleth::IEntityDescriptor* provider) const=0;
        virtual ~IApplication() {}
    };

        struct SHIBTARGET_EXPORTS ISessionCacheEntry : public virtual shibboleth::ILockable
    {
        virtual bool isValid(time_t lifetime, time_t timeout) const=0;
        virtual const char* getClientAddress() const=0;
        virtual const char* getSerializedStatement() const=0;
        virtual const saml::SAMLAuthenticationStatement* getStatement() const=0;
        virtual void preFetch(int prefetch_window)=0;
        virtual saml::Iterator<saml::SAMLAssertion*> getAssertions()=0;
        virtual ~ISessionCacheEntry() {}
    };

    struct SHIBTARGET_EXPORTS ISessionCache : public virtual shibboleth::IPlugIn
    {
        virtual void thread_init()=0;
        virtual void thread_end()=0;
        virtual std::string generateKey() const=0;
        virtual void insert(
            const char* key,
            const IApplication* application,
            saml::SAMLAuthenticationStatement *s,
            const char* client_addr,
            saml::SAMLResponse* r=NULL,
            const shibboleth::IRoleDescriptor* source=NULL
            )=0;
        virtual ISessionCacheEntry* find(const char* key, const IApplication* application)=0;
        virtual void remove(const char* key)=0;
        virtual ~ISessionCache() {}
    };

    struct SHIBTARGET_EXPORTS IConfig : public virtual shibboleth::ILockable, public virtual IPropertySet, public virtual shibboleth::IPlugIn
    {
        virtual const IListener* getListener() const=0;
        virtual ISessionCache* getSessionCache() const=0;
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

        virtual bool init(const char* schemadir, const char* config) = 0;
        virtual void shutdown() = 0;

        enum components_t {
            Listener = 1,
            SessionCache = 2,
            Metadata = 4,
            Trust = 8,
            Credentials = 16,
            AAP = 32,
            RequestMapper = 64,
            SHARExtensions = 128,
            SHIREExtensions = 256,
            Logging = 512
        };
        void setFeatures(long enabled) {m_features = enabled;}
        bool isEnabled(components_t feature) {return (m_features & feature)>0;}
        virtual IConfig* getINI() const {return m_ini;}

        static const XMLCh SHIBTARGET_NS[];
        static ShibTargetConfig& getConfig();

    protected:
        IConfig* m_ini;
        
    private:
        unsigned long m_features;
    };

    class SHIBTARGET_EXPORTS RM
    {
    public:
        RM(const IApplication* app) : m_app(app) {}
        ~RM() {}
    
        RPCError* getAssertions(
            const char* cookie,
            const char* ip,
            std::vector<saml::SAMLAssertion*>& assertions,
            saml::SAMLAuthenticationStatement **statement = NULL
            );
        static void serialize(saml::SAMLAssertion &assertion, std::string &result);
    
    private:
        const IApplication* m_app;
    };

    class ShibMLPPriv;
    class SHIBTARGET_EXPORTS ShibMLP {
    public:
        ShibMLP();
        ~ShibMLP();

        void insert (const std::string& key, const std::string& value);
        void insert (const std::string& key, const char* value) {
          std::string v = value;
          insert (key, v);
        }
        void insert (const char* key, const std::string& value) {
          std::string k = key;
          insert (k, value);
        }
        void insert (const char* key, const char* value) {
          std::string k = key, v = value;
          insert(k,v);
        }
        void insert (RPCError& e);

        void clear () { m_map.clear(); }

        const char* run (std::istream& s, const IPropertySet* props=NULL, std::string* output=NULL);
        const char* run (const std::string& input, const IPropertySet* props=NULL, std::string* output=NULL);
        const char* run (const char* input, const IPropertySet* props=NULL, std::string* output=NULL) {
            std::string i = input;
            return run(i,props,output);
        }

    private:
        ShibMLPPriv *m_priv;
        std::map<std::string,std::string> m_map;
        std::string m_generated;
    };

  //******************************************************************************
  //
  // This is the interface you're looking for.
  //

  class HTAccessInfo {
  public:
    class RequireLine {
    public:
      bool use_line;
      std::vector<std::string> tokens;
    };

    HTAccessInfo() {}
    ~HTAccessInfo() {
      for (int k = 0; k < elements.size(); k++)
	delete elements[k];
      elements.resize(0);
    }

    std::vector<RequireLine*> elements;
    bool requireAll;
  };

  class HTGroupTable {
  public:
    virtual ~HTGroupTable() {}
    virtual bool lookup(const char *entry) = 0;
  protected:
    HTGroupTable() {}
  };

  // This usurps the existing SHIRE and RM apis into a single class.
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
    virtual void log(ShibLogLevel level, const std::string &msg);

    void log(ShibLogLevel level, const char *msg) {
      std::string s = msg;
      log(level, s);
    }

    // Get/Set a cookie for this connection
    virtual std::string getCookies(void);
    virtual void setCookie(const std::string &name, const std::string &value);

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
    virtual std::string getArgs(void);
    virtual std::string getPostData(void);

    // Clear a header, set a header
    // These APIs are used for exporting the Assertions into the
    // Headers.  It will clear some well-known headers first to make
    // sure none remain.  Then it will process the set of assertions
    // and export them via setHeader().
    virtual void clearHeader(const std::string &name);
    virtual void setHeader(const std::string &name, const std::string &value);
    virtual std::string getHeader(const std::string &name);
    virtual void setRemoteUser(const std::string &user);
    virtual std::string getRemoteUser(void);

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

    // returns the "auth type"..  if this string is not "shibboleth" then
    // the request will be denied.  Any kind of "override" should be handled
    // by the subclass before returning this value.  Note that the default
    // implementation always returns "shibboleth".
    virtual std::string getAuthType(void);

    // Note: we still need to define exactly what kind of data in contained
    // in the HTAccessInfo -- perhaps we can stub it out so non-htaccess
    // systems have something they can plug in?
    virtual HTAccessInfo* getAccessInfo(void);
    virtual HTGroupTable* getGroupTable(std::string &user);

    // We're done.  Finish up.  Send either a result (error?) page or a redirect.
    // If there are no headers supplied assume the content-type == text/html
    virtual void* sendPage(
			   const std::string &msg,
			   const std::string content_type = "text/html",
			   const std::pair<std::string, std::string> headers[] = NULL,
			   int code = 200
			   );
    void* sendPage(const char *msg) {
      std::string m = msg;
      return sendPage(m);
    }

    virtual void* sendRedirect(const std::string url);

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
    std::pair<bool,void*> doCheckAuthN(bool requireSession);
    std::pair<bool,void*> doHandlePOST(void);
    std::pair<bool,void*> doCheckAuthZ(void);
    std::pair<bool,void*> doExportAssertions(bool exportAssertion);

    //**************************************************************************
    // These APIs are for backwards-compatibility.  Hopefully they can
    // eventually go away.

    // SHIRE APIs

    // Get the session cookie name and properties for the application
    std::pair<const char*,const char*> getCookieNameProps() const;
        
    // Find the default assertion consumer service for the resource
    const char* getShireURL(const char* resource) const;
        
    // Generate a Shib 1.x AuthnRequest redirect URL for the resource
    const char* getAuthnRequest(const char* resource) const;
        
    // Process a lazy session setup request and turn it into an AuthnRequest
    const char* getLazyAuthnRequest(const char* query_string) const;
        
    // Process a POST profile submission, and return (SAMLResponse,TARGET) pair.
    std::pair<const char*,const char*>
      getFormSubmission(const char* post, unsigned int len) const;
        
    RPCError* sessionCreate(
			    const char* response,
			    const char* ip,
			    std::string &cookie
			    ) const;
    RPCError* sessionIsValid(const char* session_id, const char* ip) const;

    // RM APIS

    RPCError* getAssertions(
			    const char* cookie,
			    const char* ip,
			    std::vector<saml::SAMLAssertion*>& assertions,
			    saml::SAMLAuthenticationStatement **statement = NULL
			    ) const;
    static void serialize(saml::SAMLAssertion &assertion, std::string &result);


  protected:
    ShibTarget(void);

    // Initialize the request from the parsed URL
    // protocol == http, https, etc
    // hostname == server name
    // port == server port
    // uri == resource path
    // method == GET, POST, etc.
    void init(ShibTargetConfig *config,
	      std::string protocol, std::string hostname, int port,
	      std::string uri, std::string content_type, std::string remote_host,
	      std::string method);

  private:
    mutable ShibTargetPriv *m_priv;
  };

  //******************************************************************************
  // You probably don't care about much below this line
  // unless you are using the lower-layer APIs provided by
  // the shib target library.

    class SHIBTARGET_EXPORTS SHIRE
    {
    public:
        SHIRE(const IApplication* app) { m_st = new ShibTarget(app); }
        ~SHIRE() { delete m_st; }
        
        // Get the session cookie name and properties for the application
        std::pair<const char*,const char*> getCookieNameProps() const
	  { return m_st->getCookieNameProps(); }
        
        // Find the default assertion consumer service for the resource
        const char* getShireURL(const char* resource) const
	  { return m_st->getShireURL(resource); }
        
        // Generate a Shib 1.x AuthnRequest redirect URL for the resource
        const char* getAuthnRequest(const char* resource) const
	  { return m_st->getAuthnRequest(resource); }
        
        // Process a lazy session setup request and turn it into an AuthnRequest
        const char* getLazyAuthnRequest(const char* query_string) const
	  { return m_st->getLazyAuthnRequest(query_string); }
        
        // Process a POST profile submission, and return (SAMLResponse,TARGET) pair.
        std::pair<const char*,const char*> getFormSubmission(const char* post, unsigned int len) const
	  { return m_st->getFormSubmission(post, len); }
        
        RPCError* sessionCreate(const char* response, const char* ip, std::string &cookie) const
	  { return m_st->sessionCreate(response, ip, cookie); }
        RPCError* sessionIsValid(const char* session_id, const char* ip) const
	  { return m_st->sessionIsValid(session_id, ip); }
    
    private:
	ShibTarget *m_st;
        //const IApplication* m_app;
        //mutable std::string m_cookieName;
        //mutable std::string m_shireURL;
        //mutable std::string m_authnRequest;
        //mutable CgiParse* m_parser;
    };

}

#endif /* SHIB_TARGET_H */

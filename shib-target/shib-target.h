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
# define SHIB_SCHEMAS "/opt/shibboleth/etc/shibboleth"
# define SHIB_CONFIG "/opt/shibboleth/etc/shibboleth/shibboleth.xml"
#else
# include <shib-target/shib-paths.h>
# define SHIBTARGET_EXPORTS
#endif

#include <shib-target/shibrpc.h>

namespace shibtarget {
  
  class SHIBTARGET_EXPORTS ShibTargetException : public std::exception
  {
  public:
    explicit ShibTargetException() : m_code(SHIBRPC_OK) {}
    explicit ShibTargetException(ShibRpcStatus code, const char* msg, const shibboleth::IProvider* provider);
    explicit ShibTargetException(ShibRpcStatus code, const char* msg, const shibboleth::IProviderRole* role=NULL);
    
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
        virtual bool authorized(const saml::Iterator<saml::SAMLAssertion*>& creds) const=0;
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
        virtual const char* getTLSCred(const shibboleth::IProvider* provider) const=0;
        virtual const char* getSigningCred(const shibboleth::IProvider* provider) const=0;
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
            saml::SAMLResponse* r=NULL
            )=0;
        virtual ISessionCacheEntry* find(const char* key)=0;
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
            SHIREExtensions = 256
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

    class CgiParse;
    class SHIBTARGET_EXPORTS SHIRE
    {
    public:
        SHIRE(const IApplication* app) : m_app(app), m_parser(NULL) {}
        ~SHIRE();
    
        // Find the default assertion consumer service for the resource
        const char* getShireURL(const char* resource);
        
        // Generate a Shib 1.x AuthnRequest redirect URL for the resource
        const char* getAuthnRequest(const char* resource);
        
        // Process a lazy session setup request and turn it into an AuthnRequest
        const char* getLazyAuthnRequest(const char* query_string);
        
        // Process a POST profile submission, and return (SAMLResponse,TARGET) pair.
        std::pair<const char*,const char*> getFormSubmission(const char* post, unsigned int len);
        
        RPCError* sessionCreate(const char* response, const char* ip, std::string &cookie);
        RPCError* sessionIsValid(const char* session_id, const char* ip);
    
    private:
        const IApplication* m_app;
        std::string m_shireURL;
        std::string m_authnRequest;
        CgiParse* m_parser;
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
        ShibMLP(const IApplication* app=NULL);
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

        const char* run (std::istream& s);
        const char* run (const std::string& input);
        const char* run (const char* input) {
            std::string i = input;
            return run(i);
        }

    private:
        ShibMLPPriv *m_priv;
        std::map<std::string,std::string> m_map;
        std::string m_generated;
    };
}

#endif /* SHIB_TARGET_H */

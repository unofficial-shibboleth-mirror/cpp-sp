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


/* internal.h - internally visible declarations

   Scott Cantor
   6/29/03

   $History:$
*/

#ifndef __shibtarget_internal_h__
#define __shibtarget_internal_h__

#ifdef WIN32
# define SHIBTARGET_EXPORTS __declspec(dllexport)
#endif

// eventually we might be able to support autoconf via cygwin...
#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#include "shib-target.h"

#include <log4cpp/Category.hh>
#include <log4cpp/FixedContextCategory.hh>

#define SHIBT_L(s) shibtarget::XML::Literals::s
#define SHIBT_L_QNAME(p,s) shibtarget::XML::Literals::p##_##s
#define SHIBTRAN_LOGCAT "Shibboleth-TRANSACTION"

// Controls default logging level of console tools and other situations
// where full shibboleth.xml-based logging isn't used.
#define SHIB_LOGGING "WARN"

namespace shibtarget {

    // Wraps the actual RPC connection
    class RPCHandle
    {
    public:
        RPCHandle();
        ~RPCHandle();

        CLIENT* connect(void);  // connects and returns the CLIENT handle
        void disconnect();      // disconnects, should not return disconnected handles to pool!

    private:
        log4cpp::Category* log;
        CLIENT* m_clnt;
        IListener::ShibSocket m_sock;
    };
  
    // Manages the pool of connections
    class RPCHandlePool
    {
    public:
        RPCHandlePool() :  m_lock(shibboleth::Mutex::create()) {}
        ~RPCHandlePool();
        RPCHandle* get();
        void put(RPCHandle*);
  
    private:
        std::auto_ptr<shibboleth::Mutex> m_lock;
        std::stack<RPCHandle*> m_pool;
    };
  
    // Cleans up after use
    class RPC
    {
    public:
        RPC();
        ~RPC() {delete m_handle;}
        RPCHandle* operator->() {return m_handle;}
        void pool() {m_pool.put(m_handle); m_handle=NULL;}
    
    private:
        RPCHandlePool& m_pool;
        RPCHandle* m_handle;
    };

    // Generic class, which handles the IPropertySet configuration interface.
    // Most of the basic configuration details are exposed via this interface.
    // This implementation extracts the XML tree structure and caches it in a map
    // with the attributes stored in the various possible formats they might be fetched.
    // Elements are treated as nested IPropertySets.
    // The "trick" to this is to pass in an "exclude list" using a DOMNodeFilter. Nested
    // property sets are extracted by running a TreeWalker againt the filter for the
    // immediate children. The filter should skip any excluded elements that will be
    // processed separately.
    class XMLPropertySet : public virtual IPropertySet
    {
    public:
        XMLPropertySet() {}
        ~XMLPropertySet();

        std::pair<bool,bool> getBool(const char* name, const char* ns=NULL) const;
        std::pair<bool,const char*> getString(const char* name, const char* ns=NULL) const;
        std::pair<bool,const XMLCh*> getXMLString(const char* name, const char* ns=NULL) const;
        std::pair<bool,unsigned int> getUnsignedInt(const char* name, const char* ns=NULL) const;
        std::pair<bool,int> getInt(const char* name, const char* ns=NULL) const;
        const IPropertySet* getPropertySet(const char* name, const char* ns="urn:mace:shibboleth:target:config:1.0") const;
        const DOMElement* getElement() const {return m_root;}
    
    protected:
        void load(const DOMElement* e, log4cpp::Category& log, DOMNodeFilter* filter);

    private:
        const DOMElement* m_root;
        std::map<std::string,std::pair<char*,const XMLCh*> > m_map;
        std::map<std::string,IPropertySet*> m_nested;
    };

    // ST-aware class that maps SAML artifacts to appropriate binding information
    class STArtifactMapper : public virtual saml::SAMLBrowserProfile::ArtifactMapper
    {
    public:
        STArtifactMapper(const IApplication* application)
            : m_app(application), m_metadata(application->getMetadataProviders()), m_ctx(NULL) {}
        virtual ~STArtifactMapper() {delete m_ctx;}
    
        saml::SAMLBrowserProfile::ArtifactMapper::ArtifactMapperResponse map(const saml::SAMLArtifact* artifact);
    
    private:
        const IApplication* m_app;
        shibboleth::Metadata m_metadata;    // scopes lock around use of role descriptor by hook context
        shibboleth::ShibHTTPHook::ShibHTTPHookCallContext* m_ctx;
    };
    
    class STConfig : public ShibTargetConfig
    {
    public:
        STConfig() : m_tranLog(NULL), m_tranLogLock(NULL), m_rpcpool(NULL) {}
        ~STConfig() {}
        
        bool init(const char* schemadir, const char* config);
        void shutdown();
        
        RPCHandlePool& getRPCHandlePool() {return *m_rpcpool;}
        log4cpp::Category& getTransactionLog() { m_tranLogLock->lock(); return *m_tranLog; }
        void releaseTransactionLog() { m_tranLogLock->unlock();}
    private:
        RPCHandlePool* m_rpcpool;
        log4cpp::FixedContextCategory* m_tranLog;
        shibboleth::Mutex* m_tranLogLock;
        static IConfig* ShibTargetConfigFactory(const DOMElement* e);
    };

    class XML
    {
    public:
        static const XMLCh SHIBTARGET_SCHEMA_ID[];
    
        static const char htaccessType[];
        static const char MemorySessionCacheType[];
        static const char MySQLSessionCacheType[];
        static const char RequestMapType[];
        static const char TCPListenerType[];
        static const char UnixListenerType[];
    
        struct Literals
        {
            static const XMLCh AAPProvider[];
            static const XMLCh AccessControlProvider[];
            static const XMLCh AND[];
            static const XMLCh applicationId[];
            static const XMLCh Application[];
            static const XMLCh Applications[];
            static const XMLCh CredentialsProvider[];
            static const XMLCh CredentialUse[];
            static const XMLCh Extensions[];
            static const XMLCh fatal[];
            static const XMLCh FederationProvider[];
            static const XMLCh Host[];
            static const XMLCh htaccess[];
            static const XMLCh Implementation[];
            static const XMLCh Library[];
            static const XMLCh Listener[];
            static const XMLCh logger[];
            static const XMLCh MemorySessionCache[];
            static const XMLCh MySQLSessionCache[];
            static const XMLCh name[];
            static const XMLCh Name[];
            static const XMLCh NOT[];
            static const XMLCh OR[];
            static const XMLCh Path[];
            static const XMLCh path[];
            static const XMLCh RelyingParty[];
            static const XMLCh RequestMap[];
            static const XMLCh RequestMapProvider[];
            static const XMLCh require[];
            static const XMLCh RevocationProvider[];
            static const XMLCh Rule[];
            static const XMLCh SessionCache[];
            static const XMLCh SHAR[];
            static const XMLCh ShibbolethTargetConfig[];
            static const XMLCh SHIRE[];
            static const XMLCh Signing[];
            static const XMLCh TCPListener[];
            static const XMLCh TLS[];
            static const XMLCh TrustProvider[];
            static const XMLCh type[];
            static const XMLCh UnixListener[];
        };
    };
}

#endif

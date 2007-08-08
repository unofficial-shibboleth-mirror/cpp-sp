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
#include "hresult.h"

#if defined(HAVE_LOG4SHIB)
# include <log4shib/Category.hh>
# include <log4shib/CategoryStream.hh>
# include <log4shib/FixedContextCategory.hh>
namespace shibtarget {
    namespace logging = log4shib;
};
#elif defined(HAVE_LOG4CPP)
# include <log4cpp/Category.hh>
# include <log4cpp/CategoryStream.hh>
# include <log4cpp/FixedContextCategory.hh>
namespace shibtarget {
    namespace logging = log4cpp;
};
#else
# error "Supported logging library not available."
#endif

#define SHIBT_L(s) shibtarget::XML::Literals::s
#define SHIBT_L_QNAME(p,s) shibtarget::XML::Literals::p##_##s
#define SHIBT_LOGCAT "shibtarget"
#define SHIBTRAN_LOGCAT "Shibboleth-TRANSACTION"

// Controls default logging level of console tools and other situations
// where full shibboleth.xml-based logging isn't used.
#define SHIB_LOGGING "WARN"

namespace shibtarget {

    class RPCHandlePool;
    class RPCListener : public virtual IListener
    {
    public:
        RPCListener(const DOMElement* e);
        ~RPCListener();

        void sessionNew(
            const IApplication* application,
            int supported_profiles,
            const char* recipient,
            const char* packet,
            const char* ip,
            std::string& target,
            std::string& cookie,
            std::string& provider_id
            ) const;
    
        void sessionGet(
            const IApplication* application,
            const char* cookie,
            const char* ip,
            ISessionCacheEntry** pentry
            ) const;
    
        void sessionEnd(
            const IApplication* application,
            const char* cookie
        ) const;
        
        void ping(int& i) const;

        // Implemented by socket-specific subclasses. Return type must be ONC CLIENT*
        virtual void* getClientHandle(ShibSocket& s, u_long program, u_long version) const=0;

    protected:
        logging::Category* log;
    
    private:
        mutable RPCHandlePool* m_rpcpool;
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
    
        void load(
            const DOMElement* e,    // root element of property set
            logging::Category& log, // log object for tracing
            DOMNodeFilter* filter,  // control what subelements to include
            const std::map<std::string,std::string>* remapper=NULL   // on the fly property renaming for legacy support
            );

    private:
        const DOMElement* m_root;
        std::map<std::string,std::pair<char*,const XMLCh*> > m_map;
        std::map<std::string,IPropertySet*> m_nested;
    };

    // ST-aware class that maps SAML artifacts to appropriate binding information
    class STArtifactMapper : public virtual saml::SAMLBrowserProfile::ArtifactMapper
    {
    public:
        STArtifactMapper(const IApplication* application) : m_app(application) {}
        virtual ~STArtifactMapper() {}
        saml::SAMLResponse* resolve(saml::SAMLRequest* request);
    
    private:
        const IApplication* m_app;
    };

    // Error template class
    class ShibMLPPriv;
    class ShibMLP {
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
        void insert (saml::SAMLException& e);

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
    
    class STConfig : public ShibTargetConfig
    {
    public:
        STConfig() : m_tranLog(NULL), m_tranLogLock(NULL) {}
        ~STConfig() {}
        
        bool init(const char* schemadir);
        bool load(const char* config);
        void shutdown();
        
        logging::Category& getTransactionLog() { m_tranLogLock->lock(); return *m_tranLog; }
        void releaseTransactionLog() { m_tranLogLock->unlock();}
    private:
        logging::FixedContextCategory* m_tranLog;
        shibboleth::Mutex* m_tranLogLock;
        static IConfig* ShibTargetConfigFactory(const DOMElement* e);
    };
}

#endif

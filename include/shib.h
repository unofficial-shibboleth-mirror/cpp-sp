/* shib.h - Shibboleth header file

   Scott Cantor
   6/4/02

   $History:$
*/

#ifndef __shib_h__
#define __shib_h__

#include <saml.h>

#ifdef WIN32
# ifndef SHIB_EXPORTS
#  define SHIB_EXPORTS __declspec(dllimport)
# endif
#else
# define SHIB_EXPORTS
#endif

namespace shibboleth
{
    class SHIB_EXPORTS UnsupportedProtocolException : public saml::SAMLException
    {
    public:
        explicit UnsupportedProtocolException(const char* msg) : saml::SAMLException(msg) {}
        explicit UnsupportedProtocolException(const std::string& msg) : saml::SAMLException(msg) {}
        explicit UnsupportedProtocolException(saml::QName codes[], const char* msg) : saml::SAMLException(codes,msg) {}
        explicit UnsupportedProtocolException(saml::QName codes[], const std::string& msg) : saml::SAMLException(codes, msg) {}
    };

    struct SHIB_EXPORTS Constants
    {
        static const XMLCh POLICY_CLUBSHIB[];
        static const XMLCh SHIB_ATTRIBUTE_NAMESPACE_URI[];
    };

    
    struct SHIB_EXPORTS IOriginSiteMapper
    {
        virtual saml::Iterator<saml::xstring> getHandleServiceNames(const XMLCh* originSite)=0;
        virtual void* getHandleServiceKey(const XMLCh* handleService)=0;
        virtual saml::Iterator<saml::xstring> getSecurityDomains(const XMLCh* originSite)=0;
        virtual saml::Iterator<void*> getTrustedRoots()=0;
    };

    class SHIB_EXPORTS ShibConfig
    {
    public:
        // global per-process setup and shutdown of Shibboleth runtime
        static bool init(ShibConfig* pconfig);
        static void term();

        // enables runtime and clients to access configuration
        static const ShibConfig* getConfig();

    /* start of external configuration */
        IOriginSiteMapper* origin_mapper;
    /* end of external configuration */

    private:
        static const ShibConfig* g_config;
    };


    class SHIB_EXPORTS XML
    {
    public:
        // URI constants
        static const XMLCh SHIB_NS[];
        static const XMLCh SHIB_SCHEMA_ID[];

        struct SHIB_EXPORTS Literals
        {
            // Shibboleth vocabulary

            // XML vocabulary
            static const XMLCh xmlns_shib[];
        };
    };


    class SHIB_EXPORTS SAMLBindingFactory
    {
    public:
        static saml::SAMLBinding* getInstance(const XMLCh* protocol=saml::SAMLBinding::SAML_SOAP_HTTPS);
    };
}

#endif

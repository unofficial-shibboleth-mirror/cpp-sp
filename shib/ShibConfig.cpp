/* ShibConfig.cpp - Shibboleth runtime configuration

   Scott Cantor
   6/4/02

   $History:$
*/

#ifdef WIN32
# define SHIB_EXPORTS __declspec(dllexport)
#endif

#include <shib.h>
using namespace shibboleth;

// This is currently *NOT* threadsafe code.

const ShibConfig* ShibConfig::g_config=NULL;

bool ShibConfig::init(ShibConfig* pconfig)
{
    if (!pconfig)
        return false;
    g_config=pconfig;

    // Register extension schema.
    saml::XML::registerSchema(XML::SHIB_NS,XML::SHIB_SCHEMA_ID);

    return true;
}

void ShibConfig::term()
{
}

const ShibConfig* ShibConfig::getConfig()
{
    return g_config;
}

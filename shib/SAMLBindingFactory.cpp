/* SAMLBindingFactory.cpp - SAML binding factory implementation

   Scott Cantor
   6/4/02
   
   $History:$
*/

#ifdef WIN32
# define SHIB_EXPORTS __declspec(dllexport)
#endif

#include <shib.h>
using namespace shibboleth;
using namespace saml;

SAMLBinding* SAMLBindingFactory::getInstance(const XMLCh* protocol)
{
    if (!protocol || XMLString::compareString(protocol,SAMLBinding::SAML_SOAP_HTTPS))
        throw UnsupportedProtocolException("SAMLBindingFactory::getInstance() unable to find binding implementation for specified protocol");

    return new SAMLSOAPBinding();
}

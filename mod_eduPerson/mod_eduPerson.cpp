/*
 *  mod_eduPerson.cpp
 *      Apache module to implement eduPerson Shibboleth attributes
 */

// Apache specific header files
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_core.h"
#include "http_log.h"

// SAML Runtime
#include <saml.h>
#include <shib.h>
#include <eduPerson.h>

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace eduPerson;

// per-process configuration
extern "C" module MODULE_VAR_EXPORT eduPerson_module;

extern "C" SAMLAttribute* EPPNFactory(IDOM_Element* e)
{
    return new EPPNAttribute(e);
}

extern "C" SAMLAttribute* AffiliationFactory(IDOM_Element* e)
{
    return new AffiliationAttribute(e);
}

extern "C" SAMLAttribute* PrimaryAffiliationFactory(IDOM_Element* e)
{
    return new PrimaryAffiliationAttribute(e);
}

extern "C" SAMLAttribute* EntitlementFactory(IDOM_Element* e)
{
    return new EntitlementAttribute(e);
}

/* 
 * eduPerson_child_init()
 *  Things to do when the child process is initialized.
 */
extern "C" void eduPerson_child_init(server_rec* s, pool* p)
{
    // Register extension schema and attribute factories.
    saml::XML::registerSchema(eduPerson::XML::EDUPERSON_NS,eduPerson::XML::EDUPERSON_SCHEMA_ID);

    SAMLAttribute::regFactory(eduPerson::Constants::EDUPERSON_PRINCIPAL_NAME,
			      shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI,
			      &EPPNFactory);
    SAMLAttribute::regFactory(eduPerson::Constants::EDUPERSON_AFFILIATION,
			      shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI,
			      &AffiliationFactory);
    SAMLAttribute::regFactory(eduPerson::Constants::EDUPERSON_PRIMARY_AFFILIATION,
			      shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI,
			      &PrimaryAffiliationFactory);
    SAMLAttribute::regFactory(eduPerson::Constants::EDUPERSON_ENTITLEMENT,
			      shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI,
			      &EntitlementFactory);

    std::fprintf(stderr,"eduPerson_child_init() done\n");
}


/*
 * eduPerson_child_exit()
 *  Cleanup.
 */
extern "C" void eduPerson_child_exit(server_rec* s, pool* p)
{
    SAMLAttribute::unregFactory(eduPerson::Constants::EDUPERSON_PRINCIPAL_NAME,
				shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI);
    SAMLAttribute::unregFactory(eduPerson::Constants::EDUPERSON_AFFILIATION,
				shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI);
    SAMLAttribute::unregFactory(eduPerson::Constants::EDUPERSON_PRIMARY_AFFILIATION,
				shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI);
    SAMLAttribute::unregFactory(eduPerson::Constants::EDUPERSON_ENTITLEMENT,
				shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI);

    std::fprintf(stderr,"eduPerson_child_exit() done\n");
}

extern "C"{
module MODULE_VAR_EXPORT eduPerson_module = {
    STANDARD_MODULE_STUFF,
    NULL,			/* initializer */
    NULL,	                /* dir config creater */
    NULL,			/* dir merger --- default is to override */
    NULL,	                /* server config */
    NULL,               	/* merge server config */
    NULL,			/* command table */
    NULL,			/* handlers */
    NULL,			/* filename translation */
    NULL,       		/* check_user_id */
    NULL,       		/* check auth */
    NULL,			/* check access */
    NULL,			/* type_checker */
    NULL,			/* fixups */
    NULL,			/* logger */
    NULL,			/* header parser */
    eduPerson_child_init,	/* child_init */
    eduPerson_child_exit,	/* child_exit */
    NULL			/* post read-request */
};
}

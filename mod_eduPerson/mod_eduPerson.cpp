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

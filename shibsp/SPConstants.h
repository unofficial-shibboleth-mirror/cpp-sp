/*
 *  Copyright 2001-2006 Internet2
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

/**
 * @file shibsp/SPConstants.h
 * 
 * Shibboleth SP XML constants. 
 */

#ifndef __shibsp_constants_h__
#define __shibsp_constants_h__

#include <shibsp/base.h>
#include <saml/util/SAMLConstants.h>

/**
 * Shibboleth SP XML constants.
 */
namespace shibspconstants {

    /**  Shibboleth Metadata XML namespace ("urn:mace:shibboleth:metadata:1.0") */
    extern SHIBSP_API const XMLCh SHIBMD_NS[];

    /** Shibboleth Metadata QName prefix ("shibmd") */
    extern SHIBSP_API const XMLCh SHIBMD_PREFIX[];

    /** Shibboleth 1.x Protocol Enumeration constant ("urn:mace:shibboleth:1.0") */
    extern SHIBSP_API const XMLCh SHIB1_PROTOCOL_ENUM[];

    /** Shibboleth 1.x URI AttributeNamespace constant ("urn:mace:shibboleth:1.0:attributeNamespace:uri") */
    extern SHIBSP_API const XMLCh SHIB1_ATTRIBUTE_NAMESPACE_URI[];

    /** Shibboleth 1.x transient NameIdentifier Format constant ("urn:mace:shibboleth:1.0:nameIdentifier") */
    extern SHIBSP_API const XMLCh SHIB1_NAMEID_FORMAT_URI[];

    /** Shibboleth 1.x AuthnRequest binding/profile ("urn:mace:shibboleth:1.0:profiles:AuthnRequest") */
    extern SHIBSP_API const XMLCh SHIB1_AUTHNREQUEST_PROFILE_URI[];

    /** Shibboleth 1.3 SessionInit binding/profile ("urn:mace:shibboleth:sp:1.3:SessionInit") */
    extern SHIBSP_API const XMLCh SHIB1_SESSIONINIT_PROFILE_URI[];

    /** Shibboleth 1.3 Local Logout binding/profile ("urn:mace:shibboleth:sp:1.3:Logout") */
    extern SHIBSP_API const XMLCh SHIB1_LOGOUT_PROFILE_URI[];
};

#endif /* __shibsp_constants_h__ */
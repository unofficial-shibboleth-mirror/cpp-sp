/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * @file shibsp/util/SPConstants.h
 * 
 * Shibboleth SP XML constants.
 */

#ifndef __shibsp_constants_h__
#define __shibsp_constants_h__

#include <shibsp/base.h>
#include <xercesc/util/XercesDefs.hpp>

/**
 * Shibboleth SP XML constants.
 */
namespace shibspconstants {

    /**  Shibboleth Metadata XML namespace ("urn:mace:shibboleth:metadata:1.0") */
    extern SHIBSP_API const XMLCh SHIBMD_NS[];

    /** Shibboleth Metadata QName prefix ("shibmd") */
    extern SHIBSP_API const XMLCh SHIBMD_PREFIX[];

    /** "Current" Shibboleth SP configuration namespace */
    extern SHIBSP_API const XMLCh* SHIBSPCONFIG_NS;

    /** Shibboleth 3.0 SP configuration namespace ("urn:mace:shibboleth:3.0:native:sp:config") */
    extern SHIBSP_API const XMLCh SHIB3SPCONFIG_NS[];

    /** Shibboleth 2.0 SP configuration namespace ("urn:mace:shibboleth:2.0:native:sp:config") */
    extern SHIBSP_API const XMLCh SHIB2SPCONFIG_NS[];

    /** Shibboleth 2.0 notification namespace ("urn:mace:shibboleth:2.0:sp:notify") */
    extern SHIBSP_API const XMLCh SHIB2SPNOTIFY_NS[];

    /** Shibboleth 1.x Protocol Enumeration constant ("urn:mace:shibboleth:1.0") */
    extern SHIBSP_API const XMLCh SHIB1_PROTOCOL_ENUM[];

    /** Shibboleth 1.x URI AttributeNamespace constant ("urn:mace:shibboleth:1.0:attributeNamespace:uri") */
    extern SHIBSP_API const XMLCh SHIB1_ATTRIBUTE_NAMESPACE_URI[];

    /** Shibboleth 1.x transient NameIdentifier Format constant ("urn:mace:shibboleth:1.0:nameIdentifier") */
    extern SHIBSP_API const XMLCh SHIB1_NAMEID_FORMAT_URI[];

    /** Shibboleth 1.x AuthnRequest binding/profile ("urn:mace:shibboleth:1.0:profiles:AuthnRequest") */
    extern SHIBSP_API const XMLCh SHIB1_AUTHNREQUEST_PROFILE_URI[];

    /** Shibboleth 2 filesystem-based SAML binding ("urn:mace:shibboleth:2.0:bindings:File") */
    extern SHIBSP_API const XMLCh SHIB2_BINDING_FILE[];

    /** Shibboleth 1.3 SessionInit binding/profile ("urn:mace:shibboleth:sp:1.3:SessionInit") */
    extern SHIBSP_API const char SHIB1_SESSIONINIT_PROFILE_URI[];

    /** Shibboleth 1.3 Local Logout binding/profile ("urn:mace:shibboleth:sp:1.3:Logout") */
    extern SHIBSP_API const char SHIB1_LOGOUT_PROFILE_URI[];
    
    /** "Current" Shibboleth SP configuration namespace */
    extern SHIBSP_API const char* ASCII_SHIBSPCONFIG_NS;

    /** Shibboleth 3.0 SP configuration namespace ("urn:mace:shibboleth:3.0:native:sp:config") */
    extern SHIBSP_API const char ASCII_SHIB3SPCONFIG_NS[];

    /** Shibboleth 2.0 SP configuration namespace ("urn:mace:shibboleth:2.0:native:sp:config") */
    extern SHIBSP_API const char ASCII_SHIB2SPCONFIG_NS[];
};

#endif /* __shibsp_constants_h__ */

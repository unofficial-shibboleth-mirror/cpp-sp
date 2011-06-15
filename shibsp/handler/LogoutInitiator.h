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
 * @file shibsp/handler/LogoutInitiator.h
 * 
 * Pluggable runtime functionality that handles initiating logout.
 */

#ifndef __shibsp_logoutinitiator_h__
#define __shibsp_logoutinitiator_h__

#include <shibsp/handler/LogoutHandler.h>

namespace shibsp {

    /**
     * Pluggable runtime functionality that handles initiating logout.
     */
    class SHIBSP_API LogoutInitiator : public LogoutHandler
    {
    protected:
        LogoutInitiator();
    public:
        virtual ~LogoutInitiator();

#ifndef SHIBSP_LITE
        const char* getType() const;
#endif
    };
    
    /** Registers LogoutInitiator implementations. */
    void SHIBSP_API registerLogoutInitiators();

    /** LogoutInitiator that iterates through a set of protocol-specific versions. */
    #define CHAINING_LOGOUT_INITIATOR "Chaining"

    /** LogoutInitiator that supports SAML 2.0 LogoutRequests. */
    #define SAML2_LOGOUT_INITIATOR "SAML2"

    /** LogoutInitiator that supports local-only logout. */
    #define LOCAL_LOGOUT_INITIATOR "Local"
};

#endif /* __shibsp_logoutinitiator_h__ */

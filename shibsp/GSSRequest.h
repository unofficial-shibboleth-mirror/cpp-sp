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
 * @file shibsp/GSSRequest.h
 *
 * Interface to a GSS-authenticated request.
 */

#if !defined(__shibsp_gssreq_h__) && defined(SHIBSP_HAVE_GSSAPI)
#define __shibsp_gssreq_h__

#include <shibsp/base.h>
#include <xmltooling/io/GenericRequest.h>

#ifdef SHIBSP_HAVE_GSSGNU
# include <gss.h>
#elif defined SHIBSP_HAVE_GSSMIT
# include <gssapi/gssapi.h>
# include <gssapi/gssapi_generic.h>
#else
# include <gssapi.h>
#endif

namespace shibsp {

    /**
     * Interface to a GSS-authenticated request.
     */
    class SHIBSP_API GSSRequest : public virtual xmltooling::GenericRequest
    {
    protected:
        GSSRequest();
    public:
        virtual ~GSSRequest();

        /**
         * Returns the GSS-API context established for this request, or
         * GSS_C_NO_CONTEXT if none is available.
         *
         * @return  a GSS-API context handle, or GSS_C_NO_CONTEXT
         */
        virtual gss_ctx_id_t getGSSContext() const=0;
    };
};

#endif /* __shibsp_gssreq_h__ */

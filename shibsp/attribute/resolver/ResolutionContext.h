/*
 *  Copyright 2001-2007 Internet2
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
 * @file shibsp/attribute/resolver/ResolutionContext.h
 * 
 * A context for a resolution request.
 */

#ifndef __shibsp_resctx_h__
#define __shibsp_resctx_h__

#include <shibsp/base.h>

#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/metadata/Metadata.h>

namespace shibsp {

    class SHIBSP_API Application;
    class SHIBSP_API Session;

    /**
     * A context for a resolution request.
     */
    class SHIBSP_API ResolutionContext
    {
        MAKE_NONCOPYABLE(ResolutionContext);
    protected:
        ResolutionContext() {}
    public:
        virtual ~ResolutionContext() {}

        /**
         * Returns the application resolving the attributes.
         * 
         * @return  the resolving application
         */
        virtual const Application& getApplication() const=0;
        
        /**
         * Returns the address of the client associated with the subject.
         * 
         * @return  the client's network address
         */
        virtual const char* getClientAddress() const=0;

        /**
         * Returns the metadata for the IdP associated with the subject, if any.
         * 
         * @return the IdP's metadata, or NULL
         */
        virtual const opensaml::saml2md::EntityDescriptor* getEntityDescriptor() const=0;

        /**
         * Returns the NameID associated with the subject
         * 
         * <p>SAML 1.x identifiers will be promoted to the 2.0 type.
         * 
         * @return reference to a SAML 2.0 NameID
         */
        virtual const opensaml::saml2::NameID& getNameID() const=0;

        /**
         * Returns the SSO token associated with the subject, if any.
         * 
         * @return the SSO token, or NULL
         */
        virtual const opensaml::RootObject* getSSOToken() const=0;
        
        /**
         * Returns the active session associated with the subject, if any.
         * 
         * @return the active, locked session, or NULL
         */
        virtual const Session* getSession() const=0;
        
        /**
         * Returns the set of Attributes resolved and added to the context.
         * 
         * <p>Any Attributes left in the returned container will be freed by the
         * context, so the caller should modify/clear the container after copying
         * objects for its own use.
         * 
         * @return  a mutable array of Attributes.
         */
        virtual std::vector<Attribute*>& getResolvedAttributes()=0;

        /**
         * Returns the set of assertions resolved and added to the context.
         * 
         * <p>Any assertions left in the returned container will be freed by the
         * context, so the caller should modify/clear the container after copying
         * objects for its own use.
         * 
         * @return  a mutable array of Assertions
         */
        virtual std::vector<opensaml::RootObject*>& getResolvedAssertions()=0;
    };
};

#endif /* __shibsp_resctx_h__ */

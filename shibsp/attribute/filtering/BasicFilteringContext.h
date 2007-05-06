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
 * @file shibsp/attribute/filtering/BasicFilteringContext.h
 * 
 * A trivial FilteringContext implementation.
 */

#ifndef __shibsp_basicfiltctx_h__
#define __shibsp_basicfiltctx_h__

#include <shibsp/attribute/filtering/FilteringContext.h>

namespace shibsp {

    class SHIBSP_API BasicFilteringContext : public FilteringContext
    {
    public:
        /**
         * Constructor.
         *
         * @param app   reference to Application
         * @param role  metadata role of attribute issuer, if any
         */
        BasicFilteringContext(const Application& app, const opensaml::saml2md::RoleDescriptor* role)
                : m_app(app), m_role(role), m_issuer(NULL) {
            if (role)
                m_issuer = dynamic_cast<opensaml::saml2md::EntityDescriptor*>(role->getParent())->getEntityID();
        }

        virtual ~BasicFilteringContext() {}

        const Application& getApplication() const {
            return m_app;
        }
        const XMLCh* getAttributeRequester() const {
            return m_app.getXMLString("entityID").second;
        }
        const XMLCh* getAttributeIssuer() const {
            return m_issuer;
        }
        const opensaml::saml2md::RoleDescriptor* getAttributeRequesterMetadata() const {
            return NULL;
        }
        const opensaml::saml2md::RoleDescriptor* getAttributeIssuerMetadata() const {
            return m_role;
        }

    private:
        const Application& m_app;
        const opensaml::saml2md::RoleDescriptor* m_role;
        const XMLCh* m_issuer;
    };
};

#endif /* __shibsp_basicfiltctx_h__ */

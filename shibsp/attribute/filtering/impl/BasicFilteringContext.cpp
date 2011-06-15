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
 * BasicFilteringContext.cpp
 * 
 * A trivial FilteringContext implementation.
 */

#include "internal.h"
#include "Application.h"
#include "attribute/Attribute.h"
#include "attribute/filtering/BasicFilteringContext.h"

#include <saml/saml2/metadata/Metadata.h>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace std;

FilteringContext::FilteringContext()
{
}

FilteringContext::~FilteringContext()
{
}

BasicFilteringContext::BasicFilteringContext(
    const Application& app,
    const vector<Attribute*>& attributes,
    const RoleDescriptor* role,
    const XMLCh* authncontext_class,
    const XMLCh* authncontext_decl
    ) : m_app(app), m_role(role), m_issuer(nullptr), m_class(authncontext_class), m_decl(authncontext_decl)
{
    if (role)
        m_issuer = dynamic_cast<EntityDescriptor*>(role->getParent())->getEntityID();
    for (vector<Attribute*>::const_iterator a = attributes.begin(); a != attributes.end(); ++a)
        m_attributes.insert(multimap<string,Attribute*>::value_type((*a)->getId(), *a));
}

BasicFilteringContext::~BasicFilteringContext()
{
}

const Application& BasicFilteringContext::getApplication() const
{
    return m_app;
}

const XMLCh* BasicFilteringContext::getAuthnContextClassRef() const
{
    return m_class;
}

const XMLCh* BasicFilteringContext::getAuthnContextDeclRef() const
{
    return m_decl;
}

const XMLCh* BasicFilteringContext::getAttributeRequester() const
{
    if (getAttributeIssuerMetadata()) {
        return getApplication().getRelyingParty(
            dynamic_cast<const EntityDescriptor*>(getAttributeIssuerMetadata()->getParent())
            )->getXMLString("entityID").second;
    }
    return getApplication().getRelyingParty(getAttributeIssuer())->getXMLString("entityID").second;
}

const XMLCh* BasicFilteringContext::getAttributeIssuer() const
{
    return m_issuer;
}

const RoleDescriptor* BasicFilteringContext::getAttributeRequesterMetadata() const
{
    return nullptr;
}

const RoleDescriptor* BasicFilteringContext::getAttributeIssuerMetadata() const
{
    return m_role;
}

const multimap<string,Attribute*>& BasicFilteringContext::getAttributes() const
{
    return m_attributes;
}

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
 * AttributeScopeMatchesShibMDScopeFunctor.cpp
 * 
 * A match function that ensures that an attributes value's scope matches
 * a scope given in metadata for the entity or role.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/Attribute.h"
#include "attribute/filtering/FilteringContext.h"
#include "attribute/filtering/FilterPolicyContext.h"
#include "attribute/filtering/MatchFunctor.h"
#include "metadata/MetadataExt.h"

#include <saml/saml2/metadata/Metadata.h>
#include <xercesc/util/regx/RegularExpression.hpp>

using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace std;

namespace shibsp {

    /**
     * A match function that ensures that a string matches a scope given in metadata for the entity or role.
     */
    class SHIBSP_DLLLOCAL AbstractAttributeMatchesShibMDScopeFunctor : public MatchFunctor
    {
    public:
        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            throw AttributeFilteringException("Metadata scope matching not usable as a PolicyRequirement.");
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            const RoleDescriptor* issuer = filterContext.getAttributeIssuerMetadata();
            if (!issuer)
                return false;

            const char* s = getStringToMatch(attribute, index);
            if (!s || !*s)
                return false;
            auto_arrayptr<XMLCh> widestr(fromUTF8(s));

            const Scope* rule;
            const Extensions* ext = issuer->getExtensions();
            if (ext) {
                const vector<XMLObject*>& exts = ext->getUnknownXMLObjects();
                for (vector<XMLObject*>::const_iterator e = exts.begin(); e != exts.end(); ++e) {
                    rule = dynamic_cast<const Scope*>(*e);
                    if (rule && matches(*rule, widestr)) {
                        return true;
                    }
                }
            }

            ext = dynamic_cast<const EntityDescriptor*>(issuer->getParent())->getExtensions();
            if (ext) {
                const vector<XMLObject*>& exts = ext->getUnknownXMLObjects();
                for (vector<XMLObject*>::const_iterator e = exts.begin(); e != exts.end(); ++e) {
                    rule = dynamic_cast<const Scope*>(*e);
                    if (rule && matches(*rule, widestr)) {
                        return true;
                    }
                }
            }

            return false;
        }

    protected:
        virtual const char* getStringToMatch(const Attribute& attribute, size_t index) const = 0;

    private:
        bool matches(const Scope& rule, auto_arrayptr<XMLCh>& scope) const {
            const XMLCh* val = rule.getValue();
            if (val && *val) {
                if (rule.Regexp()) {
                    try {
                        RegularExpression re(val);
                        return re.matches(scope.get());
                    }
                    catch (XMLException& ex) {
                        xmltooling::auto_ptr_char temp(ex.getMessage());
                        throw ConfigurationException(temp.get());
                    }
                }
                else {
                    return XMLString::equals(val, scope.get());
                }
            }
            return false;
        }
    };

    class AttributeScopeMatchesShibMDScopeFunctor : public AbstractAttributeMatchesShibMDScopeFunctor
    {
    protected:
        const char* getStringToMatch(const Attribute& attribute, size_t index) const {
            return attribute.getScope(index);
        }
    };

    class AttributeValueMatchesShibMDScopeFunctor : public AbstractAttributeMatchesShibMDScopeFunctor
    {
    protected:
        const char* getStringToMatch(const Attribute& attribute, size_t index) const {
            return attribute.getString(index);
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL AttributeScopeMatchesShibMDScopeFactory(const pair<const FilterPolicyContext*,const DOMElement*>& p, bool)
    {
        return new AttributeScopeMatchesShibMDScopeFunctor();
    }

    MatchFunctor* SHIBSP_DLLLOCAL AttributeValueMatchesShibMDScopeFactory(const pair<const FilterPolicyContext*,const DOMElement*>& p, bool)
    {
        return new AttributeValueMatchesShibMDScopeFunctor();
    }

};

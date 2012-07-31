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
 * @file shibsp/security/SecurityPolicyProvider.h
 * 
 * Interface to a source of security policy settings and rules.
 */

#ifndef __shibsp_policyfactory_h__
#define __shibsp_policyfactory_h__

#ifndef SHIBSP_LITE

#include <shibsp/base.h>

#include <vector>
#include <xmltooling/Lockable.h>
#include <xmltooling/unicode.h>

namespace xmltooling {
    class XMLTOOL_API QName;
};

namespace opensaml {
    class SAML_API SecurityPolicyRule;
};

namespace shibsp {

    class SHIBSP_API Application;
    class SHIBSP_API PropertySet;
    class SHIBSP_API SecurityPolicy;

    /**
     * Interface to a source of security policy settings and rules.
     */
	class SHIBSP_API SecurityPolicyProvider : public virtual xmltooling::Lockable
    {
        MAKE_NONCOPYABLE(SecurityPolicyProvider);
    protected:
        SecurityPolicyProvider();

        /** Default algorithms to block in the current release. */
        std::vector<xmltooling::xstring> m_defaultBlacklist;

    public:
        virtual ~SecurityPolicyProvider();
        
        /**
		 * Returns the security policy settings for an identified policy.
         *
		 * @param id    identifies the policy to return, or nullptr for default
         * @return a PropertySet
		 */
        virtual const PropertySet* getPolicySettings(const char* id=nullptr) const=0;

        /**
		 * Returns the security policy rules for an identified policy.
         *
		 * @param id    identifies the policy to return, or nullptr for default
         * @return an array of policy rules
		 */
        virtual const std::vector<const opensaml::SecurityPolicyRule*>& getPolicyRules(const char* id=nullptr) const=0;

        /**
         * Returns a default/implicit set of XML Signature/Encryption algorithm identifiers to block.
         *
         * @return  an array of algorithm URIs to block
         */
        virtual const std::vector<xmltooling::xstring>& getDefaultAlgorithmBlacklist() const;

        /**
         * Returns a set of XML Signature/Encryption algorithm identifiers to block.
         *
         * @return  an array of algorithm URIs to block
         */
        virtual const std::vector<xmltooling::xstring>& getAlgorithmBlacklist() const=0;

        /**
         * Returns a set of XML Signature/Encryption algorithm identifiers to permit.
         *
         * @return  an array of algorithm URIs to permit
         */
        virtual const std::vector<xmltooling::xstring>& getAlgorithmWhitelist() const=0;

        /**
         * Returns a SecurityPolicy applicable to an application and/or policy identifier.
         *
         * <p>The caller <strong>MUST</strong> lock the application's MetadataProvider for the life
         * of the returned object.
         *
         * @param application   reference to application applying policy
         * @param role          identifies the role (generally IdP or SP) of the policy peer
         * @param policyId      identifies policy, defaults to the application's default
         * @return  a new policy instance, which the caller is responsible for freeing
         */
        virtual SecurityPolicy* createSecurityPolicy(
            const Application& application, const xmltooling::QName* role, const char* policyId=nullptr
            ) const;
    };

    /**
     * Registers SecurityPolicyProvider classes into the runtime.
     */
    void SHIBSP_API registerSecurityPolicyProviders();

    /** SecurityPolicyProvider based on an XML configuration format. */
    #define XML_SECURITYPOLICY_PROVIDER "XML"
};

#endif

#endif /* __shibsp_policyfactory_h__ */

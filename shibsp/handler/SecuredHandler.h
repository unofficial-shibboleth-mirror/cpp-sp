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
 * @file shibsp/handler/SecuredHandler.h
 * 
 * Pluggable runtime functionality that is protected by simple access control.
 */

#ifndef __shibsp_securedhandler_h__
#define __shibsp_securedhandler_h__

#include <shibsp/handler/AbstractHandler.h>
#include <shibsp/util/IPRange.h>

#include <vector>

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    /**
     * Pluggable runtime functionality that is protected by simple access control.
     */
    class SHIBSP_API SecuredHandler : public AbstractHandler
    {
    protected:
        /**
         * Constructor
         * 
         * @param e             DOM element to load as property set
         * @param log           logging category to use
         * @param aclProperty   name of IP/CIDR ACL property
         * @param defaultACL    IP/CIDR ACL to apply if no acl property is set
         * @param filter        optional filter controls what child elements to include as nested PropertySets
         * @param remapper      optional property rename mapper for legacy property support
         */
        SecuredHandler(
            const xercesc::DOMElement* e,
            xmltooling::logging::Category& log,
            const char* aclProperty="acl",
            const char* defaultACL=nullptr,
            xercesc::DOMNodeFilter* filter=nullptr,
            const Remapper* remapper=nullptr
            );

    public:
        virtual ~SecuredHandler();

        std::pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

    private:
        void parseACL(const std::string& acl);
        std::vector<IPRange> m_acl;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_securedhandler_h__ */

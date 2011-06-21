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
 * DummyAttributeFilter.cpp
 * 
 * Pathological AttributeFilter that rejects all attributes.
 */

#include "internal.h"
#include "attribute/Attribute.h"
#include "attribute/filtering/AttributeFilter.h"

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {

    class SHIBSP_DLLLOCAL DummyAttributeFilter : public AttributeFilter
    {
    public:
        DummyAttributeFilter(const DOMElement* e) {
        }
        virtual ~DummyAttributeFilter() {
        }
        
        Lockable* lock() {
            return this;
        }
        void unlock() {
        }
        
        void filterAttributes(const FilteringContext& context, vector<Attribute*>& attributes) const {
            Category::getInstance(SHIBSP_LOGCAT".AttributeFilter.Dummy").warn("filtering out all attributes");
            for_each(attributes.begin(), attributes.end(), xmltooling::cleanup<Attribute>());
            attributes.clear();
        }
    };

    AttributeFilter* SHIBSP_DLLLOCAL DummyAttributeFilterFactory(const DOMElement* const & e)
    {
        return new DummyAttributeFilter(e);
    }
};

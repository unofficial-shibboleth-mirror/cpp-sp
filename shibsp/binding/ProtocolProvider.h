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
 * @file shibsp/binding/ProtocolProvider.h
 * 
 * Interface to protocol, binding, and default endpoint information.
 */

#ifndef __shibsp_protprov_h__
#define __shibsp_protprov_h__

#include <shibsp/base.h>

#include <vector>
#include <xmltooling/Lockable.h>

namespace shibsp {

    class SHIBSP_API PropertySet;

    /**
     * Interface to protocol, binding, and default endpoint information.
     */
	class SHIBSP_API ProtocolProvider : public virtual xmltooling::Lockable
    {
        MAKE_NONCOPYABLE(ProtocolProvider);
    protected:
        ProtocolProvider();
    public:
        virtual ~ProtocolProvider();
    
        /**
         * Returns configuration details for initiating a protocol service, as a PropertySet.
         *
         * @param protocol  the name of a protocol
         * @param service   the name of a service
         * @return  a PropertySet associated with initiation/request of a service
         */
        virtual const PropertySet* getInitiator(const char* protocol, const char* service) const=0;

        /**
         * Returns an ordered array of protocol bindings available for a specified service.
         *
         * @param protocol  the name of a protocol
         * @param service   name of the protocol service
         * @return  the array of bindings, each represented as a PropertySet
         */
        virtual const std::vector<const PropertySet*>& getBindings(const char* protocol, const char* service) const=0;
    };

    /**
     * Registers ProtocolProvider classes into the runtime.
     */
    void SHIBSP_API registerProtocolProviders();

    /** ProtocolProvider based on an XML configuration format. */
    #define XML_PROTOCOL_PROVIDER "XML"
};

#endif /* __shibsp_protprov_h__ */

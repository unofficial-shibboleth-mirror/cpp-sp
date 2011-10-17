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
 * @file shibsp/util/IPRange.h
 * 
 * Represents a range of IP addresses.
 */

#ifndef __shibsp_iprange_h__
#define __shibsp_iprange_h__

#include <shibsp/base.h>

#include <bitset>

#ifdef WIN32
# include <winsock2.h>
#elif defined(SHIBSP_HAVE_SYS_SOCKET_H)
# include <sys/socket.h>
#endif

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * Represents a range of IP addresses.
     */
    class SHIBSP_API IPRange
    {
    public:
        /**
         * Constructor.
         *
         * @param address address to base the range on; may be the network address or the
         *                address of a host within the network
         * @param maskSize the number of bits in the netmask
         */
        IPRange(const std::bitset<32>& address, int maskSize);

        /**
         * Constructor.
         *
         * @param address address to base the range on; may be the network address or the
         *                address of a host within the network
         * @param maskSize the number of bits in the netmask
         */
        IPRange(const std::bitset<128>& address, int maskSize);

        /**
         * Determines whether the given address is contained in the IP range.
         *
         * @param address the address to check
         *
         * @return true iff the address is in the range
         */
        bool contains(const char* address) const;

        /**
         * Determines whether the given address is contained in the IP range.
         *
         * @param address the address to check
         *
         * @return true iff the address is in the range
         */
        bool contains(const struct sockaddr* address) const;

        /**
         * Parses a CIDR block definition in to an IP range.
         *
         * @param cidrBlock the CIDR block definition
         *
         * @return the resultant IP range
         */
        static IPRange parseCIDRBlock(const char* cidrBlock);

    private:
        /** Number of bits within the address.  32 bits for IPv4 address, 128 bits for IPv6 addresses. */
        int m_addressLength;

        /** The IP network address for the range. */
        std::bitset<32> m_network4;

        /** The netmask for the range. */
        std::bitset<32> m_mask4;

        /** The IP network address for the range. */
        std::bitset<128> m_network6;

        /** The netmask for the range. */
        std::bitset<128> m_mask6;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_iprange_h__ */

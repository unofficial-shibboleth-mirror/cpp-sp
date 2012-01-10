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
 * @file IPRange.cpp
 * 
 * Represents a range of IP addresses.
 */

#include "internal.h"
#include "exceptions.h"
#include "util/IPRange.h"

#include <xmltooling/logging.h>

#ifdef WIN32
# include <winsock2.h>
# include <ws2tcpip.h>
#else
# include <netdb.h>
# include <netinet/in.h>
#endif

using namespace shibsp;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace {
    // Gets the byte-level representation of a numeric IP address.
    struct addrinfo* parseIPAddress(const char* s)
    {
        struct addrinfo* ret = nullptr;
        struct addrinfo hints;

        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_NUMERICHOST;
        hints.ai_family = AF_UNSPEC;

        if (getaddrinfo(s, nullptr, &hints, &ret) != 0)
            return nullptr;
        if (ret) {
            if (ret->ai_family != AF_INET
#ifdef AF_INET6
                && ret->ai_family != AF_INET6
#endif
                ) {
                freeaddrinfo(ret);
                return nullptr;
            }
        }
        return ret;
    }
};

IPRange::IPRange(const bitset<32>& address, int maskSize) : m_addressLength(32)
{
    if (maskSize < 0 || maskSize > m_addressLength)
        throw ConfigurationException("CIDR prefix length out of range.");

    for (int i = m_addressLength - maskSize; i < m_addressLength; ++i)
        m_mask4.set(i, true);

    m_network4 = address;
    m_network4 &= m_mask4;
}

IPRange::IPRange(const bitset<128>& address, int maskSize) : m_addressLength(128)
{
    if (maskSize < 0 || maskSize > m_addressLength)
        throw ConfigurationException("CIDR prefix length out of range.");

    for (int i = m_addressLength - maskSize; i < m_addressLength; ++i)
        m_mask6.set(i, true);

    m_network6 = address;
    m_network6 &= m_mask6;
}

bool IPRange::contains(const char* address) const
{

    struct addrinfo* parsed = parseIPAddress(address);
    if (!parsed)
        return false;
    bool ret  = contains(parsed->ai_addr);
    freeaddrinfo(parsed);
    return ret;
}

bool IPRange::contains(const struct sockaddr* address) const
{

    Category& log = Category::getInstance(SHIBSP_LOGCAT".IPRange");

    if (address->sa_family == AF_INET) {
        if (m_addressLength != 32)
            return false;
        unsigned long raw = 0;
        memcpy(&raw, &((struct sockaddr_in*)address)->sin_addr, 4);
        bitset<32> rawbits((int)ntohl(raw));    // the bitset loads from a host-order variable
        if (log.isDebugEnabled()) {
            log.debug(
                "comparing address (%s) to network (%s) with mask (%s)",
                rawbits.to_string< char, char_traits<char>, allocator<char> >().c_str(),
                m_network4.to_string< char, char_traits<char>, allocator<char> >().c_str(),
                m_mask4.to_string< char, char_traits<char>, allocator<char> >().c_str()
                );
        }
        rawbits &= m_mask4;
        return (rawbits == m_network4);
    }
#ifdef AF_INET6
    else if (address->sa_family == AF_INET6) {
        if (m_addressLength != 128)
            return false;
        unsigned char raw[16];
        memcpy(raw, &((struct sockaddr_in6*)address)->sin6_addr, 16);
        bitset<128> rawbits(raw[0]);
        for (int i = 1; i < 16; ++i) {
            rawbits <<= 8;
            rawbits |= bitset<128>(raw[i]);
        }
        if (log.isDebugEnabled()) {
            log.debug(
                "comparing address (%s) to network (%s) with mask (%s)",
                rawbits.to_string< char, char_traits<char>, allocator<char> >().c_str(),
                m_network6.to_string< char, char_traits<char>, allocator<char> >().c_str(),
                m_mask6.to_string< char, char_traits<char>, allocator<char> >().c_str()
                );
        }
        rawbits &= m_mask6;
        return (rawbits == m_network6);
    }
#endif
    return false;
}

IPRange IPRange::parseCIDRBlock(const char* cidrBlock)
{
    string block = cidrBlock;
    string::size_type sep = block.find("/");
    if (sep == string::npos) {
        if (block.find(":") == string::npos)
            block += "/32";
        else
            block += "/128";
        sep = block.find("/");
    }
    struct addrinfo* address = parseIPAddress(block.substr(0, sep).c_str());
    if (!address)
        throw ConfigurationException("Unable to parse address in CIDR block.");
    int maskSize = atoi(block.substr(++sep).c_str());
    if (address->ai_family == AF_INET) {
         unsigned long raw = 0;
         memcpy(&raw, &((struct sockaddr_in*)address->ai_addr)->sin_addr, 4);
         freeaddrinfo(address);
         bitset<32> rawbits((int)ntohl(raw));    // the bitset loads from a host-order variable
         return IPRange(rawbits, maskSize);
    }
#ifdef AF_INET6
    else if (address->ai_family == AF_INET6) {
        unsigned char raw[16];
        memcpy(raw, &((struct sockaddr_in6*)address->ai_addr)->sin6_addr, 16);
        freeaddrinfo(address);
        bitset<128> rawbits(raw[0]);
        for (int i = 1; i < 16; ++i) {
            rawbits <<= 8;
            rawbits |= bitset<128>(raw[i]);
        }
        return IPRange(rawbits, maskSize);
    }
#endif
    throw ConfigurationException("Unrecognized address type in CIDR block.");
}

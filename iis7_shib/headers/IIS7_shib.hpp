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
#pragma once

// Windows
#include <Windows.h>
#include <http.h>
#include "httpserv.h"

//
// Miscelanea
//
#include <set>
#include <list>
#include <boost/lexical_cast.hpp>
#include <string>

// Load Santurio with a bracketed warning off
#pragma warning(push)
#pragma warning(disable:4005)
#include <xsec\framework\XSECDefs.hpp>
#pragma warning(pop)

// Shibboleth
#define SHIBSP_LITE
#include "config_win32.h"
#include <shibsp/SPConfig.h>
#include <shibsp/ServiceProvider.h>
#include <shibsp/util/PropertySet.h>

#include <xmltooling/util/XMLHelper.h>
#include <xmltooling/Lockable.h>
#include <shibsp/exceptions.h>

#include <message.h>

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace boost;
using namespace std;
// globals
namespace Config {
    static const XMLCh path[] =             UNICODE_LITERAL_4(p, a, t, h);
    static const XMLCh validate[] =         UNICODE_LITERAL_8(v, a, l, i, d, a, t, e);
    static const XMLCh name[] =             UNICODE_LITERAL_4(n, a, m, e);
    static const XMLCh port[] =             UNICODE_LITERAL_4(p, o, r, t);
    static const XMLCh sslport[] =          UNICODE_LITERAL_7(s, s, l, p, o, r, t);
    static const XMLCh scheme[] =           UNICODE_LITERAL_6(s, c, h, e, m, e);
    static const XMLCh id[] =               UNICODE_LITERAL_2(i, d);
    static const XMLCh useHeaders[] =       UNICODE_LITERAL_10(u, s, e, H, e, a, d, e, r, s);
    static const XMLCh theAttribute[] =     UNICODE_LITERAL_9(a, t, t, r, i, b, u, t, e);
    static const XMLCh thePrefix[] =        UNICODE_LITERAL_6(p, r, e, f, i, x);
    static const XMLCh useVariables[] =     UNICODE_LITERAL_12(u, s, e, V, a, r, i, a, b, l, e, s);
    static const XMLCh Alias[] =            UNICODE_LITERAL_5(A, l, i, a, s);
    static const XMLCh Site[] =             UNICODE_LITERAL_4(S, i, t, e);
    static const XMLCh Role[] =             UNICODE_LITERAL_4(R, o, l, e);

    static const char* SpoofHeaderName = "ShibSpoofCheck";

    extern HINSTANCE g_hinstDLL;
    extern SPConfig* g_Config;
    extern bool g_bNormalizeRequest;
    extern string g_unsetHeaderValue, g_spoofKey;
    extern bool g_checkSpoofing;
    extern bool g_catchAll;
    extern bool g_bSafeHeaderNames;
    extern bool g_bUseHeaders;
    extern bool g_bUseVariables;
    extern vector<string> g_NoCerts;


    struct site_t {
        site_t(const DOMElement* e)
            : m_name(XMLHelper::getAttrString(e, "", name)),
            m_scheme(XMLHelper::getAttrString(e, "", scheme)),
            m_port(XMLHelper::getAttrString(e, "", port)),
            m_sslport(XMLHelper::getAttrString(e, "", sslport)),
            m_useHeaders(XMLHelper::getAttrBool(e, g_bUseHeaders, useHeaders)),
            m_useVariables(XMLHelper::getAttrBool(e, g_bUseVariables, useVariables))
        {
            e = XMLHelper::getFirstChildElement(e, Alias);
            while (e) {
                if (e->hasChildNodes()) {
                    auto_ptr_char alias(e->getTextContent());
                    m_aliases.insert(alias.get());
                }
                e = XMLHelper::getNextSiblingElement(e, Alias);
            }
        }
        string m_scheme, m_port, m_sslport, m_name;
        bool m_useHeaders, m_useVariables;
        set<string> m_aliases;
    };

    extern map<string, site_t> g_Sites;

    extern wstring g_authNRole;
    extern vector<string> g_RoleAttributeNames;
}

BOOL LogEvent(
    LPCSTR  lpUNCServerName,
    WORD  wType,
    DWORD  dwEventID,
    PSID  lpUserSid,
    LPCSTR  message);
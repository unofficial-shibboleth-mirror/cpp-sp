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
 * TransactionLog.cpp
 *
 * Formatted event record logging.
 */

#include "internal.h"

#if defined(XMLTOOLING_LOG4SHIB)
# ifndef SHIBSP_LOG4SHIB
#  error "Logging library mismatch (XMLTooling is using log4shib)."
# endif
#elif defined(XMLTOOLING_LOG4CPP)
# ifndef SHIBSP_LOG4CPP
#  error "Logging library mismatch (XMLTooling is using log4cpp)."
# endif
#else
# error "No supported logging library."
#endif

#include "Application.h"
#include "SessionCache.h"
#include "TransactionLog.h"
#include "attribute/Attribute.h"

#include <saml/saml1/core/Assertions.h>
#include <saml/saml1/core/Protocols.h>
#include <saml/saml2/core/Protocols.h>
#include <saml/saml2/metadata/Metadata.h>
#include <xmltooling/util/Threads.h>

using namespace shibsp;
using namespace opensaml::saml1;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    TransactionLog::Event* SHIBSP_DLLLOCAL LoginEventFactory(void* const &)
    {
        return new LoginEvent();
    }

    TransactionLog::Event* SHIBSP_DLLLOCAL LogoutEventFactory(void* const &)
    {
        return new LogoutEvent();
    }

    TransactionLog::Event* SHIBSP_DLLLOCAL AuthnRequestEventFactory(void* const &)
    {
        return new AuthnRequestEvent();
    }
};

void SHIBSP_API shibsp::registerEvents()
{
    SPConfig& conf=SPConfig::getConfig();
    conf.EventManager.registerFactory(LOGIN_EVENT, LoginEventFactory);
    conf.EventManager.registerFactory(LOGOUT_EVENT, LogoutEventFactory);
    conf.EventManager.registerFactory(AUTHNREQUEST_EVENT, AuthnRequestEventFactory);
}

TransactionLog::TransactionLog(const char* fmt, const char* absent)
    : log(logging::Category::getInstance(SHIBSP_TX_LOGCAT)), m_lock(Mutex::create()), m_absent(absent ? absent : "")
{
    // Split the formatting string into named '%' parameter tokens, and "other stuff" to be echoed
    // literally in log messages.

    bool in_token = false;
    m_formatting.push_back(string());
    vector<string>::iterator field = m_formatting.begin();
    while (fmt && *fmt) {
        if (in_token) {
            if (!isalnum(*fmt) && *fmt != '-' && *fmt != '%') {
                m_formatting.push_back(string());
                field = m_formatting.begin() + m_formatting.size() - 1;
                in_token = false;
            }
        }
        else if (*fmt == '%') {
            if (!field->empty()) {
                m_formatting.push_back(string());
                field = m_formatting.begin() + m_formatting.size() - 1;
            }
            in_token = true;
        }
        *field += *fmt++;
    }
    if (!m_formatting.empty() && m_formatting.back().empty())
        m_formatting.pop_back();
}

TransactionLog::~TransactionLog()
{
}

Lockable* TransactionLog::lock()
{
    m_lock->lock();
    return this;
}

void TransactionLog::unlock()
{
    m_lock->unlock();
}

void TransactionLog::write(const TransactionLog::Event& e)
{
    if (m_formatting.empty()) {
        // For compatibility, we support the old transaction log format, ugly though it may be.
        // The session log line would be easy to emulate, but the old attribute logging isn't
        // easy to represent with a formatting string.

        ostringstream os;

        const LoginEvent* login = dynamic_cast<const LoginEvent*>(&e);
        if (login) {
            os << "New session (ID: ";
            login->write(os, "%s", nullptr);
            os << ") with (applicationId: ";
            login->write(os, "%app", nullptr);
            os << ") for principal from (IdP: ";
            login->write(os, "%IDP", "none");
            os << ") at (ClientAddress: ";
            login->write(os, "%a", nullptr);
            os << ") with (NameIdentifier: ";
            login->write(os, "%n", "none");
            os << ") using (Protocol: ";
            login->write(os, "%p", "none");
            os << ") from (AssertionID: ";
            login->write(os, "%i", nullptr);
            os << ")";

            Locker locker(this);
            log.info(os.str());
            os.str("");

            os << "Cached the following attributes with session (ID: ";
            login->write(os, "%s", nullptr);
            os << ") for (applicationId: ";
            login->write(os, "%app", nullptr);
            os << ") {";
            log.info(os.str());

            if (login->m_attributes) {
                for (vector<Attribute*>::const_iterator a=login->m_attributes->begin(); a != login->m_attributes->end(); ++a)
                    log.infoStream() << "\t" << (*a)->getId() << " (" << (*a)->valueCount() << " values)";
            }

            log.info("}");
            return;
        }

        const LogoutEvent* logout = dynamic_cast<const LogoutEvent*>(&e);
        if (logout && (logout->m_sessionID || logout->m_session || !logout->m_sessions.empty())) {
            os << "Destroyed session (applicationId: ";
            logout->write(os, "%app", nullptr);
            os << ") (ID: ";
            logout->write(os, "%s", nullptr);
            os << ")";
            log.info(os.str());
            return;
        }
    }
    else {
        ostringstream os;
        for (vector<string>::const_iterator i = m_formatting.begin(); i != m_formatting.end() && !i->empty(); ++i) {
            if ((*i)[0] != '%' || !e.write(os, i->c_str(), m_absent.c_str())) {
                os << *i;
            }
        }
        Category::getInstance(string(SHIBSP_TX_LOGCAT) + "." + e.getType()).info(os.str());
    }
}

namespace {
    bool _URL(const TransactionLog::Event& e, ostream& os) {
        const HTTPRequest* http = dynamic_cast<const HTTPRequest*>(e.m_request);
        if (http) {
            os << http->getRequestURL();
            return true;
        }
        return false;
    }

    bool _URI(const TransactionLog::Event& e, ostream& os) {
        const HTTPRequest* http = dynamic_cast<const HTTPRequest*>(e.m_request);
        if (http) {
            os << http->getRequestURI();
            return true;
        }
        return false;
    }

    bool _Header(const TransactionLog::Event& e, ostream& os, const char* name) {
        const HTTPRequest* http = dynamic_cast<const HTTPRequest*>(e.m_request);
        if (http) {
            string s = http->getHeader(name);
            if (!s.empty()) {
                os << s;
                return true;
            }
        }
        return false;
    }

    bool _ExceptionMessage(const TransactionLog::Event& e, ostream& os) {
        if (e.m_exception && e.m_exception->what()) {
            os << e.m_exception->what();
            return true;
        }
        return false;
    }

    bool _ExceptionType(const TransactionLog::Event& e, ostream& os) {
        const XMLToolingException* x = dynamic_cast<const XMLToolingException*>(e.m_exception);
        if (x) {
            os << x->getClassName();
            return true;
        }
        return false;
    }

    bool _AssertionID(const TransactionLog::Event& e, ostream& os) {
        const XMLCh* id = nullptr;
        const LoginEvent* login = dynamic_cast<const LoginEvent*>(&e);
        if (login) {
            if (login->m_saml2AuthnStatement) {
                const saml2::Assertion* a = dynamic_cast<const saml2::Assertion*>(login->m_saml2AuthnStatement->getParent());
                if (a)
                    id = a->getID();
            }
            else if (login->m_saml1AuthnStatement) {
                const saml1::Assertion* a = dynamic_cast<const saml1::Assertion*>(login->m_saml1AuthnStatement->getParent());
                if (a)
                    id = a->getAssertionID();
            }
        }
        if (id && *id) {
            auto_ptr_char temp(id);
            os << temp.get();
            return true;
        }
        return false;
    }

    bool _ProtocolID(const TransactionLog::Event& e, ostream& os) {
        const XMLCh* id = nullptr;
        const LoginEvent* login = dynamic_cast<const LoginEvent*>(&e);
        if (login) {
            if (login->m_saml2Response)
                id = login->m_saml2Response->getID();
            else if (login->m_saml1Response)
                id = login->m_saml1Response->getResponseID();
        }
        else {
            const AuthnRequestEvent* request = dynamic_cast<const AuthnRequestEvent*>(&e);
            if (request) {
                if (request->m_saml2Request)
                    id = request->m_saml2Request->getID();
            }
            else {
                const LogoutEvent* logout = dynamic_cast<const LogoutEvent*>(&e);
                if (logout) {
                    if (logout->m_saml2Request)
                        id = logout->m_saml2Request->getID();
                    else if (logout->m_saml2Response)
                        id = logout->m_saml2Response->getID();
                }
            }
        }
        if (id && *id) {
            auto_ptr_char temp(id);
            os << temp.get();
            return true;
        }
        return false;
    }

    bool _InResponseTo(const TransactionLog::Event& e, ostream& os) {
        const XMLCh* id = nullptr;
        const LoginEvent* login = dynamic_cast<const LoginEvent*>(&e);
        if (login) {
            if (login->m_saml2Response)
                id = login->m_saml2Response->getInResponseTo();
            else if (login->m_saml1Response)
                id = login->m_saml1Response->getInResponseTo();
        }
        else {
            const LogoutEvent* logout = dynamic_cast<const LogoutEvent*>(&e);
            if (logout && logout->m_saml2Response) {
                id = logout->m_saml2Response->getInResponseTo();
            }
        }
        if (id && *id) {
            auto_ptr_char temp(id);
            os << temp.get();
            return true;
        }
        return false;
    }

    bool _StatusCode(const TransactionLog::Event& e, ostream& os) {
        const saml1p::Status* s1 = nullptr;
        const saml2p::Status* s2 = nullptr;
        const LoginEvent* login = dynamic_cast<const LoginEvent*>(&e);
        if (login) {
            if (login->m_saml2Response)
                s2 = login->m_saml2Response->getStatus();
            else if (login->m_saml1Response)
                s1 = login->m_saml1Response->getStatus();
        }
        else {
            const LogoutEvent* logout = dynamic_cast<const LogoutEvent*>(&e);
            if (logout && logout->m_saml2Response)
                s2 = logout->m_saml2Response->getStatus();
        }

        if (s2 && s2->getStatusCode() && s2->getStatusCode()->getValue()) {
            auto_ptr_char temp(s2->getStatusCode()->getValue());
            if (temp.get() && *temp.get()) {
                os << temp.get();
                return true;
            }
        }
        else if (s1 && s1->getStatusCode() && s1->getStatusCode()->getValue()) {
            os << s1->getStatusCode()->getValue()->toString();
            return true;
        }

        const XMLToolingException* x = dynamic_cast<const XMLToolingException*>(e.m_exception);
        if (x) {
            const char* s = x->getProperty("statusCode");
            if (s && *s) {
                os << s;
                return true;
            }
        }
        return false;
    }

    bool _SubStatusCode(const TransactionLog::Event& e, ostream& os) {
        const saml1p::Status* s1 = nullptr;
        const saml2p::Status* s2 = nullptr;
        const LoginEvent* login = dynamic_cast<const LoginEvent*>(&e);
        if (login) {
            if (login->m_saml2Response)
                s2 = login->m_saml2Response->getStatus();
            else if (login->m_saml1Response)
                s1 = login->m_saml1Response->getStatus();
        }
        else {
            const LogoutEvent* logout = dynamic_cast<const LogoutEvent*>(&e);
            if (logout && logout->m_saml2Response)
                s2 = logout->m_saml2Response->getStatus();
        }

        if (s2 && s2->getStatusCode() && s2->getStatusCode()->getStatusCode()) {
            auto_ptr_char temp(s2->getStatusCode()->getStatusCode()->getValue());
            if (temp.get() && *temp.get()) {
                os << temp.get();
                return true;
            }
        }
        else if (s1 && s1->getStatusCode() && s1->getStatusCode()->getStatusCode()) {
            if (s1->getStatusCode()->getStatusCode()->getValue()) {
                os << s1->getStatusCode()->getValue()->toString();
                return true;
            }
        }

        const XMLToolingException* x = dynamic_cast<const XMLToolingException*>(e.m_exception);
        if (x) {
            const char* s = x->getProperty("statusCode2");
            if (s && *s) {
                os << s;
                return true;
            }
        }
        return false;
    }

    bool _StatusMessage(const TransactionLog::Event& e, ostream& os) {
        const XMLCh* msg = nullptr;
        const saml1p::Status* s1 = nullptr;
        const saml2p::Status* s2 = nullptr;
        const LoginEvent* login = dynamic_cast<const LoginEvent*>(&e);
        if (login) {
            if (login->m_saml2Response)
                s2 = login->m_saml2Response->getStatus();
            else if (login->m_saml1Response)
                s1 = login->m_saml1Response->getStatus();
        }
        else {
            const LogoutEvent* logout = dynamic_cast<const LogoutEvent*>(&e);
            if (logout && logout->m_saml2Response)
                s2 = logout->m_saml2Response->getStatus();
        }

        if (s2 && s2->getStatusMessage())
            msg = s2->getStatusMessage()->getMessage();
        else if (s1 && s1->getStatusMessage())
            msg = s1->getStatusMessage()->getMessage();

        if (msg) {
            auto_ptr_char temp(msg);
            if (temp.get() && *temp.get()) {
                os << temp.get();
                return true;
            }
        }
        else {
            const XMLToolingException* x = dynamic_cast<const XMLToolingException*>(e.m_exception);
            if (x) {
                const char* s = x->getProperty("statusMessage");
                if (s && *s) {
                    os << s;
                    return true;
                }
            }
        }

        return false;
    }

    bool _AssertionIssueInstant(const TransactionLog::Event& e, ostream& os) {
        time_t t = 0;
        const LoginEvent* login = dynamic_cast<const LoginEvent*>(&e);
        if (login) {
            if (login->m_saml2AuthnStatement) {
                const saml2::Assertion* a = dynamic_cast<const saml2::Assertion*>(login->m_saml2AuthnStatement->getParent());
                if (a && a->getIssueInstant())
                    t = a->getIssueInstantEpoch();
            }
            else if (login->m_saml1AuthnStatement) {
                const saml1::Assertion* a = dynamic_cast<const saml1::Assertion*>(login->m_saml1AuthnStatement->getParent());
                if (a && a->getIssueInstant())
                    t = a->getIssueInstantEpoch();
            }
        }
        if (t == 0)
            return false;
#ifndef HAVE_LOCALTIME_R
        struct tm* ptime=localtime(&t);
#else
        struct tm res;
        struct tm* ptime=localtime_r(&t, &res);
#endif
        char timebuf[32];
        strftime(timebuf,32,"%Y-%m-%dT%H:%M:%S",ptime);
        os << timebuf;
        return true;
    }

    bool _ProtocolIssueInstant(const TransactionLog::Event& e, ostream& os) {
        time_t t = 0;
        const LoginEvent* login = dynamic_cast<const LoginEvent*>(&e);
        if (login) {
            if (login->m_saml2Response && login->m_saml2Response->getIssueInstant())
                t = login->m_saml2Response->getIssueInstantEpoch();
            else if (login->m_saml1Response && login->m_saml1Response->getIssueInstant())
                t = login->m_saml1Response->getIssueInstantEpoch();
        }
        else {
            const AuthnRequestEvent* request = dynamic_cast<const AuthnRequestEvent*>(&e);
            if (request) {
                if (request->m_saml2Request && request->m_saml2Request->getIssueInstant())
                    t = request->m_saml2Request->getIssueInstantEpoch();
            }
            else {
                const LogoutEvent* logout = dynamic_cast<const LogoutEvent*>(&e);
                if (logout) {
                    if (logout->m_saml2Request && logout->m_saml2Request->getIssueInstant())
                        t = logout->m_saml2Request->getIssueInstantEpoch();
                    else if (logout->m_saml2Response && logout->m_saml2Response->getIssueInstant())
                        t = logout->m_saml2Response->getIssueInstantEpoch();
                }
            }
        }
        if (t == 0)
            return false;
#ifndef HAVE_LOCALTIME_R
        struct tm* ptime=localtime(&t);
#else
        struct tm res;
        struct tm* ptime=localtime_r(&t, &res);
#endif
        char timebuf[32];
        strftime(timebuf,32,"%Y-%m-%dT%H:%M:%S",ptime);
        os << timebuf;
        return true;
    }

    bool _AuthnInstant(const TransactionLog::Event& e, ostream& os) {
        time_t t = 0;
        const LoginEvent* login = dynamic_cast<const LoginEvent*>(&e);
        if (login) {
            if (login->m_saml2AuthnStatement && login->m_saml2AuthnStatement->getAuthnInstant())
                t = login->m_saml2AuthnStatement->getAuthnInstantEpoch();
            else if (login->m_saml1AuthnStatement && login->m_saml1AuthnStatement->getAuthenticationInstant())
                t = login->m_saml1AuthnStatement->getAuthenticationInstantEpoch();
        }
        if (t == 0)
            return false;
#ifndef HAVE_LOCALTIME_R
        struct tm* ptime=localtime(&t);
#else
        struct tm res;
        struct tm* ptime=localtime_r(&t, &res);
#endif
        char timebuf[32];
        strftime(timebuf,32,"%Y-%m-%dT%H:%M:%S",ptime);
        os << timebuf;
        return true;
    }

    bool _SessionIndex(const TransactionLog::Event& e, ostream& os) {
        const LoginEvent* login = dynamic_cast<const LoginEvent*>(&e);
        if (login) {
            if (login->m_saml2AuthnStatement && login->m_saml2AuthnStatement->getSessionIndex()) {
                auto_ptr_char ix(login->m_saml2AuthnStatement->getSessionIndex());
                if (ix.get() && *ix.get()) {
                    os << ix.get();
                    return true;
                }
            }
        }
        else {
            const LogoutEvent* logout = dynamic_cast<const LogoutEvent*>(&e);
            if (logout && logout->m_saml2Request && !logout->m_saml2Request->getSessionIndexs().empty()) {
                const vector<saml2p::SessionIndex*>& indexes = logout->m_saml2Request->getSessionIndexs();
                for (vector<saml2p::SessionIndex*>::const_iterator i = indexes.begin(); i != indexes.end(); ++i) {
                    auto_ptr_char ix((*i)->getSessionIndex());
                    if (ix.get() && *ix.get()) {
                        if (i != indexes.begin())
                            os << ',';
                        os << ix.get();
                    }
                }
                return true;
            }
        }
        return false;
    }

    bool _SessionID(const TransactionLog::Event& e, ostream& os) {
        const LogoutEvent* logout = dynamic_cast<const LogoutEvent*>(&e);
        if (logout) {
            if (!logout->m_sessions.empty()) {
                for (vector<string>::const_iterator s = logout->m_sessions.begin(); s != logout->m_sessions.end(); ++s) {
                    if (s != logout->m_sessions.begin())
                        os << ',';
                    os << *s;
                }
                return true;
            }
            else if (logout->m_session) {
                os << logout->m_session->getID();
                return true;
            }
        }
        else if (e.m_sessionID) {
            os << e.m_sessionID;
            return true;
        }
        return false;
    }

    bool _REMOTE_USER(const TransactionLog::Event& e, ostream& os) {
        const LoginEvent* login = dynamic_cast<const LoginEvent*>(&e);
        const LogoutEvent* logout = dynamic_cast<const LogoutEvent*>(&e);
        if (e.m_app && ((login && login->m_attributes) || (logout && logout->m_session))) {
            const vector<string>& ids = e.m_app->getRemoteUserAttributeIds();
            const vector<shibsp::Attribute*>& attrs = (login ? *login->m_attributes : logout->m_session->getAttributes());
            for (vector<string>::const_iterator id = ids.begin(); id != ids.end(); ++id) {
                for (vector<shibsp::Attribute*>::const_iterator a = attrs.begin(); a != attrs.end(); ++a) {
                    if (*id == (*a)->getId() && (*a)->valueCount() > 0) {
                        os << (*a)->getSerializedValues().front();
                        return true;
                    }
                }
            }
        }
        return false;
    }

    bool _REMOTE_ADDR(const TransactionLog::Event& e, ostream& os) {
        if (e.m_request) {
            string s = e.m_request->getRemoteAddr();
            if (!s.empty()) {
                os << s;
                return true;
            }
        }
        return false;
    }

    bool _AuthnContext(const TransactionLog::Event& e, ostream& os) {
        const LoginEvent* login = dynamic_cast<const LoginEvent*>(&e);
        if (login) {
            if (login->m_saml2AuthnStatement && login->m_saml2AuthnStatement->getAuthnContext()) {
                const AuthnContext* ctx = login->m_saml2AuthnStatement->getAuthnContext();
                if (ctx->getAuthnContextClassRef()) {
                    auto_ptr_char ref(ctx->getAuthnContextClassRef()->getReference());
                    if (ref.get()) {
                        os << ref.get();
                        return true;
                    }
                }
                else if (ctx->getAuthnContextDeclRef()) {
                    auto_ptr_char ref(ctx->getAuthnContextDeclRef()->getReference());
                    if (ref.get()) {
                        os << ref.get();
                        return true;
                    }
                }
                else if (ctx->getAuthnContextDecl()) {
                    os << "(full declaration)";
                    return true;
                }
            }
            else if (login->m_saml1AuthnStatement && login->m_saml1AuthnStatement->getAuthenticationMethod()) {
                auto_ptr_char ac(login->m_saml1AuthnStatement->getAuthenticationMethod());
                if (ac.get()) {
                    os << ac.get();
                    return true;
                }
            }
        }
        return false;
    }

    bool _UserAgent(const TransactionLog::Event& e, ostream& os) {
        return _Header(e, os, "User-Agent");
    }

    bool _ApplicationID(const TransactionLog::Event& e, ostream& os) {
        if (e.m_app) {
            os << e.m_app->getId();
            return true;
        }
        return false;
    }

    bool _SP_(const TransactionLog::Event& e, ostream& os) {
        if (e.m_app) {
            const PropertySet* props = e.m_app->getRelyingParty(e.m_peer);
            if (props) {
                pair<bool,const char*> entityid = props->getString("entityID");
                if (entityid.first) {
                    os << entityid.second;
                    return true;
                }
            }
        }
        return false;
    }

    bool _IDP(const TransactionLog::Event& e, ostream& os) {
        if (e.m_peer) {
            auto_ptr_char entityid(e.m_peer->getEntityID());
            if (entityid.get()) {
                os << entityid.get();
                return true;
            }
        }
        
        const LogoutEvent* logout = dynamic_cast<const LogoutEvent*>(&e);
        if (logout && logout->m_session && logout->m_session->getEntityID()) {
            os << logout->m_session->getEntityID();
            return true;
        }

        return false;
    }

    bool _Protocol(const TransactionLog::Event& e, ostream& os) {
        if (e.m_protocol) {
            os << e.m_protocol;
            return true;
        }
        return false;
    }

    bool _Binding(const TransactionLog::Event& e, ostream& os) {
        if (e.m_binding) {
            os << e.m_binding;
            return true;
        }
        return false;
    }

    bool _NameID(const TransactionLog::Event& e, ostream& os) {
        if (e.m_nameID && e.m_nameID->getName()) {
            auto_ptr_char temp(e.m_nameID->getName());
            if (temp.get() && *temp.get()) {
                os << temp.get();
                return true;
            }
        }
        else {
            const AuthnRequestEvent* request = dynamic_cast<const AuthnRequestEvent*>(&e);
            if (request) {
                if (request->m_saml2Request && request->m_saml2Request->getSubject()) {
                    const saml2::NameID* n = request->m_saml2Request->getSubject()->getNameID();
                    if (n) {
                        auto_ptr_char temp(n->getName());
                        if (temp.get() && *temp.get()) {
                            os << temp.get();
                            return true;
                        }
                    }
                }
            }
            else {
                const LogoutEvent* logout = dynamic_cast<const LogoutEvent*>(&e);
                if (logout) {
                    const saml2::NameID* n = nullptr;
                    if (logout->m_session)
                        n = logout->m_session->getNameID();
                    else if (logout->m_saml2Request)
                        n = logout->m_saml2Request->getNameID();
                    if (n) {
                        auto_ptr_char temp(n->getName());
                        if (temp.get() && *temp.get()) {
                            os << temp.get();
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    bool _Attributes(const TransactionLog::Event& e, ostream& os) {
        const vector<shibsp::Attribute*>* attrs = nullptr;
        const LoginEvent* login = dynamic_cast<const LoginEvent*>(&e);
        if (login) {
            attrs = login->m_attributes;
        }
        else {
            const LogoutEvent* logout = dynamic_cast<const LogoutEvent*>(&e);
            if (logout && logout->m_session)
                attrs = &logout->m_session->getAttributes();
        }
        if (attrs && !attrs->empty()) {
            map<string,size_t> valcounts;
            for (vector<shibsp::Attribute*>::const_iterator a = attrs->begin(); a != attrs->end(); ++a) {
                valcounts[(*a)->getId()] += (*a)->valueCount();
            }
            for (map<string,size_t>::const_iterator c = valcounts.begin(); c != valcounts.end(); ++c) {
                if (c != valcounts.begin())
                    os << ',';
                os << c->first << '(' << c->second << ')';
            }
            return true;
        }
        return false;
    }

    bool _Logout(const TransactionLog::Event& e, ostream& os) {
        const LogoutEvent* logout = dynamic_cast<const LogoutEvent*>(&e);
        if (logout) {
            switch (logout->m_logoutType) {
                case LogoutEvent::LOGOUT_EVENT_INVALID:
                    os << "invalid";
                    return true;
                case LogoutEvent::LOGOUT_EVENT_LOCAL:
                    os << "local";
                    return true;
                case LogoutEvent::LOGOUT_EVENT_GLOBAL:
                    os << "global";
                    return true;
                case LogoutEvent::LOGOUT_EVENT_PARTIAL:
                    os << "partial";
                    return true;
            }
        }
        return false;
    }
};

TransactionLog::Event::Event()
    : m_exception(nullptr),
      m_request(nullptr),
      m_app(nullptr),
      m_sessionID(nullptr),
      m_peer(nullptr),
      m_protocol(nullptr),
      m_binding(nullptr),
      m_nameID(nullptr)
{
    m_handlers["e"] = _ExceptionMessage;
    m_handlers["E"] = _ExceptionType;
    m_handlers["S"] = _StatusCode;
    m_handlers["SS"] = _SubStatusCode;
    m_handlers["SM"] = _StatusMessage;
    m_handlers["URL"] = _URL;
    m_handlers["URI"] = _URI;
    m_handlers["s"] = _SessionID;
    m_handlers["a"] = _REMOTE_ADDR;
    m_handlers["UA"] = _UserAgent;
    m_handlers["app"] = _ApplicationID;
    m_handlers["SP"] = _SP_;
    m_handlers["IDP"] = _IDP;
    m_handlers["p"] = _Protocol;
    m_handlers["b"] = _Binding;
    m_handlers["n"] = _NameID;
}

TransactionLog::Event::~Event()
{
}

bool TransactionLog::Event::write(ostream& out, const char* field, const char* absent) const
{
    if (!field || *field++ != '%') {
        return false;
    }
    
    if (*field == '%' || *field == '\0') {
        out << '%';
    }
    else {
        map<string,handler_fn>::const_iterator h = m_handlers.find(field);
        if ((h != m_handlers.end() && !h->second(*this, out)) || (h == m_handlers.end() && !_Header(*this, out, field))) {
            if (absent)
                out << absent;
        }
    }
    return true;
}

LoginEvent::LoginEvent()
    : m_saml2AuthnStatement(nullptr),
      m_saml2Response(nullptr),
      m_saml1AuthnStatement(nullptr),
      m_saml1Response(nullptr),
      m_attributes(nullptr)
{
    m_handlers["u"] = _REMOTE_USER;
    m_handlers["i"] = _AssertionID;
    m_handlers["I"] = _ProtocolID;
    m_handlers["II"] = _InResponseTo;
    m_handlers["d"] = _AssertionIssueInstant;
    m_handlers["D"] = _ProtocolIssueInstant;
    m_handlers["t"] = _AuthnInstant;
    m_handlers["x"] = _SessionIndex;
    m_handlers["ac"] = _AuthnContext;
    m_handlers["attr"] = _Attributes;
}

const char* LoginEvent::getType() const
{
    return "Login";
}

LoginEvent::~LoginEvent()
{
}

LogoutEvent::LogoutEvent()
    : m_logoutType(LOGOUT_EVENT_UNKNOWN),
      m_saml2Request(nullptr),
      m_saml2Response(nullptr),
      m_session(nullptr)
{
    m_handlers["L"] = _Logout;
    m_handlers["u"] = _REMOTE_USER;
    m_handlers["I"] = _ProtocolID;
    m_handlers["II"] = _InResponseTo;
    m_handlers["D"] = _ProtocolIssueInstant;
    m_handlers["x"] = _SessionIndex;
}

LogoutEvent::~LogoutEvent()
{
}

const char* LogoutEvent::getType() const
{
    if (m_saml2Request)
        return "Logout.Request";
    else if (m_saml2Response)
        return "Logout.Response";
    return "Logout";
}

AuthnRequestEvent::AuthnRequestEvent() : m_saml2Request(nullptr)
{
    m_handlers["I"] = _ProtocolID;
    m_handlers["D"] = _ProtocolIssueInstant;
}

AuthnRequestEvent::~AuthnRequestEvent()
{
}

const char* AuthnRequestEvent::getType() const
{
    return "AuthnRequest";
}

/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * DummyRequest.h
 *
 * Mock SPRequest class for unit tests.
 */

#include "AbstractSPRequest.h"

#include <map>
#include <string>

namespace shibsp {

    class DummyRequest : public AbstractSPRequest {
    public:
        DummyRequest(const char* uri=nullptr) : AbstractSPRequest(SHIBSP_LOGCAT ".DummyRequest"), m_addr("192.168.0.1") {
            setRequestURI(uri);
        }
        const char* getRequestID() const { return nullptr; }
        const char* getMethod() const { return nullptr; }
        const char* getScheme() const { return m_scheme.c_str(); }
        const char* getHostname() const { return m_hostname.c_str(); }
        int getPort() const { return m_port; }
        std::string getContentType() const { return ""; }
        long getContentLength() const { return -1; }
        const char* getQueryString() const { return m_query.c_str(); }
        const char* getRequestBody() const { return nullptr; }
        std::string getHeader(const char* name) const {
            return m_requestHeaders.find(name) == m_requestHeaders.end() ? "" : m_requestHeaders.find(name)->second;
        }
        std::string getRemoteUser() const { return m_user; }
        std::string getRemoteAddr() const { return m_addr; }
        std::string getLocalAddr() const { return ""; }
        std::string getAuthType() const { return ""; }
        long sendResponse(std::istream&, long status) { return status; }
        void clearHeader(const char* name) {}
        void setHeader(const char* name, const char* value) {}
        void setResponseHeader(const char* name, const char* value, bool replace=false) {
            HTTPResponse::setResponseHeader(name, value, replace);
            m_responseHeaders[name] = value ? value : "";
        }
        void setRemoteUser(const char*) {}
        long returnDecline() { return 200; }
        long returnOK() { return 200; }

        bool isUseHeaders() const {return true;}
        bool isUseVariables() const { return false; }
        
        std::string m_scheme;
        std::string m_hostname;
        int m_port;
        std::string m_query;
        std::string m_user;
        std::string m_addr;
        std::map<std::string,std::string> m_requestHeaders;
        std::map<std::string,std::string> m_responseHeaders;
    };

};
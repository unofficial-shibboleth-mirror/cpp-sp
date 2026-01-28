/**
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
#pragma once

#include <shibsp/AbstractSPRequest.h>

class IIS7Request : public AbstractSPRequest {

private:
    IHttpContext* m_ctx;
    IHttpRequest* m_request;
    IHttpResponse* m_response;
    IHttpEventProvider* m_event;
    const PropertySet& m_site;
    bool m_firsttime;
    int m_port;
    string m_hostname, m_scheme;
    bool m_useVariables;
    bool m_useHeaders;
    bool m_safeHeaderNames;
    mutable string m_remoteUser;
    mutable vector<string> m_certs;
    mutable string m_body;
    mutable bool m_gotBody;
    string m_allhttp;
    set<string> m_roleAttributeNames;
    set<wstring> m_roles;

public:
    IIS7Request(
        _In_ IHttpContext *pHttpContext,
        _In_ IHttpEventProvider *pEventProvider,
        _In_ bool checkUser,
        _In_ const PropertySet& site
        );
    string makeSafeHeader(const char* rawname) const;
    bool isUseHeaders() { return m_useHeaders; }

protected:
    const char* getRequestID() const;
    const char* getScheme() const;
    const char* getHostname() const;
    int getPort() const;
    string getContentType() const;
    long getContentLength() const;
    string getRemoteUser() const;
    string getAuthType() const;
    const char* getRequestBody() const;
    const char* getQueryString() const;
    string getHeader(const char* name) const;

    bool isUseHeaders() const;
    bool isUseVariables() const;
    void setHeader(const char* name, const char* value);
    void setRemoteUser(const char* user);
    const vector<string>& getClientCertificates() const;
    const char* getMethod() const;
    void  clearHeader(const char* name);
    long  returnDecline();
    long  returnOK();
    string getRemoteAddr() const;
    string getLocalAddr() const;
    string getSecureHeader(const char* name) const;

    long sendResponse(istream& in, long status);
    void setResponseHeader(const char* name, const char* value, bool replace=false);
    long sendRedirect(const char* url);

private:
    void logFatal(const string& operation, HRESULT hr) const;
    void throwError(const string& operation, HRESULT hr) const;
    wstring utf8ToUtf16(const char* input) const;
    string  utf16ToUtf8(const wstring input) const;
};

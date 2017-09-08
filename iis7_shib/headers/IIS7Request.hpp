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

#include <shibsp/AbstractSPRequest.h>

class IIS7Request : public AbstractSPRequest {

private:
    IHttpContext  *m_ctx;
    IHttpRequest  *m_request;
    IHttpResponse  *m_response;
    IHttpEventProvider *m_event;
    bool m_firsttime;
    // TODO
    int m_port;
    string m_hostname;
    bool m_SSL;
    bool m_useVariables;
    bool m_useHeaders;
    mutable string m_remoteUser;
    mutable vector<string> m_certs;
    mutable string m_body;
    mutable bool m_gotBody;
    string m_allhttp;
    set<wstring> m_roles;

public:
    IIS7Request(_In_ IHttpContext *pHttpContext, _In_ IHttpEventProvider *pEventProvider, _In_ bool checkUser);
    string makeSafeHeader(const char* rawname) const;
    bool isUseHeaders() { return m_useHeaders; }

protected:
    //
    // AbstractSP
    //
    void setHeader(const char* name, const char* value);
    void setRemoteUser(const char* user);
    const vector<string>& getClientCertificates() const;
    const char* getMethod() const;
    void  clearHeader(const char* rawname, const char* cginame);
    long  returnDecline();
    long  returnOK();
    void  log(SPLogLevel level, const string& msg) const;
    string getRemoteAddr() const;
    string getSecureHeader(const char* name) const;
    //
    // XMLTooling::GenericRequest
    //
    const char* getScheme() const;
    const char* getHostname() const;
    int getPort() const;
    string getContentType() const;
    long getContentLength() const;
    string getRemoteUser() const;
    const char* getRequestBody() const;
    //
    // XMLTooing:: HTTPRequest
    //
    const char* getQueryString() const;
    string getHeader(const char* name) const;

    // XMLTooing:: HTTPResponse, GenericResponse
    long sendResponse(istream& in, long status);
    void setResponseHeader(const char* name, const char* value);
    long sendRedirect(const char* url);

private:
    void logFatal(const string& operation, HRESULT hr) const;
    void throwError(const string& operation, HRESULT hr) const;

};

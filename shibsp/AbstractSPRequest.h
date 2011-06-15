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
 * @file shibsp/AbstractSPRequest.h
 * 
 * Abstract base for SPRequest implementations.
 */

#ifndef __shibsp_abstreq_h__
#define __shibsp_abstreq_h__

#include <shibsp/SPRequest.h>

namespace shibsp {
    
    class SHIBSP_API CGIParser;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * Abstract base for SPRequest implementations
     */
    class SHIBSP_API AbstractSPRequest : public virtual SPRequest
    {
    protected:
        /**
         * Constructor.
         *
         * @param category  logging category to use
         */
        AbstractSPRequest(const char* category);
        
        /**
         * Stores a normalized request URI to ensure it contains no %-encoded characters
         * or other undesirable artifacts.
         *
         * @param uri   the request URI as obtained from the client
         */
        void setRequestURI(const char* uri);

    public:
        virtual ~AbstractSPRequest();

        // Virtual function overrides.
        const ServiceProvider& getServiceProvider() const;
        RequestMapper::Settings getRequestSettings() const;
        const Application& getApplication() const;
        Session* getSession(bool checkTimeout=true, bool ignoreAddress=false, bool cache=true);
        const char* getRequestURI() const;
        const char* getRequestURL() const;
        std::string getRemoteAddr() const;
        const char* getParameter(const char* name) const;
        std::vector<const char*>::size_type getParameters(const char* name, std::vector<const char*>& values) const;
        const char* getHandlerURL(const char* resource=nullptr) const;
        void log(SPLogLevel level, const std::string& msg) const;
        bool isPriorityEnabled(SPLogLevel level) const;

    private:
        ServiceProvider* m_sp;
        mutable RequestMapper* m_mapper;
        mutable RequestMapper::Settings m_settings;
        mutable const Application* m_app;
        mutable bool m_sessionTried;
        mutable Session* m_session;
        std::string m_uri;
        mutable std::string m_url;
        void* m_log; // declared void* to avoid log4cpp header conflicts in Apache
        mutable std::string m_handlerURL;
        mutable CGIParser* m_parser;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_abstreq_h__ */

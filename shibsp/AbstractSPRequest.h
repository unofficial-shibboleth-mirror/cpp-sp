/*
 *  Copyright 2001-2006 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file shibsp/AbstractSPRequest.h
 * 
 * Abstract base for SPRequest implementations  
 */

#ifndef __shibsp_abstreq_h__
#define __shibsp_abstreq_h__

#include <shibsp/exceptions.h>
#include <shibsp/SPRequest.h>

namespace shibsp {

    class SHIBSP_API CGIParser;
    
    /**
     * Abstract base for SPRequest implementations
     */
    class SHIBSP_API AbstractSPRequest : public virtual SPRequest
    {
    protected:
        /**
         * Constructor
         * 
         * @param app   pointer to effective Application, if known
         */
        AbstractSPRequest(const Application* app=NULL);
        
    public:
        virtual ~AbstractSPRequest();

        const char* getRequestURL() const {
            return m_url.c_str();
        }
        
        const Application& getSPApplication() const {
            return *m_app;
        }

        const char* getParameter(const char* name) const;

        std::vector<const char*>::size_type getParameters(const char* name, std::vector<const char*>& values) const;

        const char* getCookie(const char* name) const;

        const char* getHandlerURL(const char* resource=NULL) const;

        void log(SPLogLevel level, const std::string& msg) const;

        bool isPriorityEnabled(SPLogLevel level) const;

    protected:
        /** Holds effective Application. */
        const Application* m_app;

        /** Complete "canonical" request URL. */
        std::string m_url;
    
    private:
        void* m_log; // declared void* to avoid log4cpp header conflicts in Apache
        mutable std::string m_handlerURL;
        mutable std::map<std::string,std::string> m_cookieMap;
        mutable CGIParser* m_parser;
    };
};

#endif /* __shibsp_abstreq_h__ */

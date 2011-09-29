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
 * @file shibsp/util/CGIParser.h
 * 
 * CGI GET/POST parameter parsing.
 */

#ifndef __shibsp_cgi_h__
#define __shibsp_cgi_h__

#include <shibsp/base.h>

#include <map>
#include <string>

namespace xmltooling {
    class XMLTOOL_API HTTPRequest;
};

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * CGI GET/POST parameter parsing
     */
    class SHIBSP_API CGIParser
    {
        MAKE_NONCOPYABLE(CGIParser);
    public:
        /**
         * Constructor.
         * 
         * @param request   HTTP request interface
         * @param queryOnly true iff the POST body should be ignored
         */
        CGIParser(const xmltooling::HTTPRequest& request, bool queryOnly=false);

        ~CGIParser();

        /** Alias for multimap iterator. */
        typedef std::multimap<std::string,char*>::const_iterator walker;
        
        /**
         * Returns a pair of bounded iterators around the values of a parameter.
         * 
         * @param name  name of parameter, or nullptr to return all parameters
         * @return  a pair of multimap iterators surrounding the matching value(s)
         */
        std::pair<walker,walker> getParameters(const char* name) const;
        
    private:
        void parse(const char* pch);
        std::multimap<std::string,char*> kvp_map;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_cgi_h__ */

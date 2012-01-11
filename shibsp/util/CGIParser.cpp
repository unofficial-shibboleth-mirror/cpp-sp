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
 * CGIParser.cpp
 * 
 * CGI GET/POST parameter parsing.
 */

#include "internal.h"
#include "util/CGIParser.h"

#include <boost/bind.hpp>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/io/HTTPRequest.h>
#include <xmltooling/util/URLEncoder.h>

using namespace shibsp;
using namespace xmltooling;
using namespace boost;
using namespace std;

namespace {
    /* Parsing routines modified from NCSA source. */
    char* makeword(char *line, char stop)
    {
        int x = 0,y;
        char *word = (char *) malloc(sizeof(char) * (strlen(line) + 1));

        for(x=0;((line[x]) && (line[x] != stop));x++)
            word[x] = line[x];

        word[x] = '\0';
        if(line[x])
            ++x;
        y=0;

        while(line[x])
          line[y++] = line[x++];
        line[y] = '\0';
        return word;
    }

    char* fmakeword(char stop, size_t *cl, const char** ppch)
    {
        int wsize;
        char *word;
        int ll;

        wsize = 1024;
        ll=0;
        word = (char *) malloc(sizeof(char) * (wsize + 1));

        while(1)
        {
            word[ll] = *((*ppch)++);
            if(ll==wsize-1)
            {
                word[ll+1] = '\0';
                wsize+=1024;
                word = (char *)realloc(word,sizeof(char)*(wsize+1));
            }
            --(*cl);
            if((word[ll] == stop) || word[ll] == EOF || (!(*cl)))
            {
                if(word[ll] != stop)
                    ll++;
                word[ll] = '\0';
                return word;
            }
            ++ll;
        }
    }

    void plustospace(char *str)
    {
        register int x;

        for(x=0;str[x];x++)
            if(str[x] == '+') str[x] = ' ';
    }
}

CGIParser::CGIParser(const HTTPRequest& request, bool queryOnly)
{
    parse(request.getQueryString());
    if (!queryOnly && !strcmp(request.getMethod(),"POST")) {
        if (request.getContentType().find("application/x-www-form-urlencoded") != string::npos)
            parse(request.getRequestBody());
    }
}

CGIParser::~CGIParser()
{
    static void (*fn)(void*) = &free;
    for_each(kvp_map.begin(), kvp_map.end(), boost::bind(fn, boost::bind(&multimap<string,char*>::value_type::second, _1)));}

void CGIParser::parse(const char* pch)
{
    size_t cl = pch ? strlen(pch) : 0;
    const URLEncoder* dec = XMLToolingConfig::getConfig().getURLEncoder();
    while (cl && pch) {
        char *name;
        char *value;
        value=fmakeword('&', &cl, &pch);
        plustospace(value);
        dec->decode(value);
        name=makeword(value, '=');
        kvp_map.insert(pair<const string,char*>(name, value));
        free(name);
    }
}

pair<CGIParser::walker,CGIParser::walker> CGIParser::getParameters(const char* name) const
{
    if (name)
        return kvp_map.equal_range(name);
    return make_pair(kvp_map.begin(), kvp_map.end());
}

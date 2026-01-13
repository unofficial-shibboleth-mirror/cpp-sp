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

/**
 * handler/impl/AbstractHandler.cpp
 *
 * Base class for handlers based on a BoostPropertySet.
 */

#include "internal.h"

#include "exceptions.h"
#include "Agent.h"
#include "AgentConfig.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "logging/Category.h"
#include "remoting/RemotingService.h"
#include "util/CGIParser.h"
#include "util/Misc.h"
#include "util/SPConstants.h"
#include "util/PathResolver.h"
#include "util/URLEncoder.h"

#include <vector>
#include <fstream>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

#ifndef HAVE_STRCASECMP
# define strcasecmp _stricmp
#endif

namespace shibsp {
    //extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory SAML2LogoutFactory;
    //extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory AttributeCheckerFactory;
    //extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory MetadataGeneratorFactory;

    //extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory AdminLogoutInitiatorFactory;
    //extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory SAML2LogoutInitiatorFactory;
    //extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory LocalLogoutInitiatorFactory;

    extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory PassthroughFactory;
    extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory SessionHandlerFactory;
    extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory StatusHandlerFactory;
    extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory SessionInitiatorFactory;
    extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory TokenConsumerFactory;


    void SHIBSP_DLLLOCAL generateRandomHex(std::string& buf, unsigned int len) {
        static char DIGITS[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        int r;
        unsigned char b1,b2;
        buf.erase();
        for (unsigned int i=0; i<len; i+=4) {
            r = rand();
            b1 = (0x00FF & r);
            b2 = (0xFF00 & r)  >> 8;
            buf += (DIGITS[(0xF0 & b1) >> 4 ]);
            buf += (DIGITS[0x0F & b1]);
            buf += (DIGITS[(0xF0 & b2) >> 4 ]);
            buf += (DIGITS[0x0F & b2]);
        }
    }
};

void SHIBSP_API shibsp::registerHandlers()
{
    AgentConfig& conf=AgentConfig::getConfig();

    //conf.HandlerManager.registerFactory(ATTR_CHECKER_HANDLER, AttributeCheckerFactory);
    //conf.HandlerManager.registerFactory(METADATA_GENERATOR_HANDLER, MetadataGeneratorFactory);
 
    //conf.HandlerManager.registerFactory(SAML20_LOGOUT_HANDLER, SAML2LogoutFactory);

    //conf.HandlerManager.registerFactory(ADMIN_LOGOUT_INITIATOR, AdminLogoutInitiatorFactory);
    //conf.HandlerManager.registerFactory(SAML2_LOGOUT_INITIATOR, SAML2LogoutInitiatorFactory);
    //conf.HandlerManager.registerFactory(LOCAL_LOGOUT_INITIATOR, LocalLogoutInitiatorFactory);

    conf.HandlerManager.registerFactory(PASSTHROUGH_HANDLER, PassthroughFactory);
    conf.HandlerManager.registerFactory(STATUS_HANDLER, StatusHandlerFactory);
    conf.HandlerManager.registerFactory(SESSION_HANDLER, SessionHandlerFactory);
    conf.HandlerManager.registerFactory(SESSION_INITIATOR_HANDLER, SessionInitiatorFactory);
    conf.HandlerManager.registerFactory(TOKEN_CONSUMER_HANDLER, TokenConsumerFactory);
} 

Handler::Handler()
{
}

Handler::~Handler()
{
}

AbstractHandler::AbstractHandler(const ptree& pt) {
    load(pt);
}

AbstractHandler::~AbstractHandler()
{
}


const char* Handler::getEventType() const
{
    return nullptr;
}

DDF AbstractHandler::wrapRequest(const SPRequest& request, const set<string>& headers, bool sendBody) const
{
    DDF in = DDF("http").structure();
    in.addmember("scheme").string(request.getScheme());
    in.addmember("hostname").unsafe_string(request.getHostname());
    in.addmember("port").integer(request.getPort());
    in.addmember("content_type").string(request.getContentType().c_str());
    if (sendBody && !strcmp(request.getMethod(), "POST")) {
        if (request.getContentType().find("application/x-www-form-urlencoded") != string::npos) {
            unsigned int postLimit = getUnsignedInt(RequestMapper::POST_LIMIT_PROP_NAME, request,
                RequestMapper::POST_LIMIT_PROP_DEFAULT, HANDLER_PROPERTY_FIXED | HANDLER_PROPERTY_MAP);
            if (postLimit == 0 || request.getContentLength() <= postLimit) {
                in.addmember("body").unsafe_string(request.getRequestBody());
            }
            else {
                request.warn("POST limit exceeded, ignoring posted data");
            }
        }
        else {
            request.warn("Content type not supported, ignoring posted data");
        }
    }
    in.addmember("content_length").longinteger(request.getContentLength());
    in.addmember("remote_user").string(request.getRemoteUser().c_str());
    in.addmember("remote_addr").string(request.getRemoteAddr().c_str());
    in.addmember("local_addr").string(request.getLocalAddr().c_str());
    in.addmember("method").string(request.getMethod());
    in.addmember("uri").unsafe_string(request.getRequestURI());
    in.addmember("url").unsafe_string(request.getRequestURL());
    in.addmember("query").string(request.getQueryString());

    if (!headers.empty()) {
        string hdr;
        DDF hin = in.addmember("headers").structure();
        for (const string& h : headers) {
            hdr = request.getHeader(h.c_str());
            if (!hdr.empty())
                hin.addmember(h.c_str()).unsafe_string(hdr.c_str());
        }
    }

    return in;
}

pair<bool,long> AbstractHandler::unwrapResponse(SPRequest& request, DDF& wrappedResponse) const
{
    DDF http = wrappedResponse["http"];
    DDF h = http["headers"];
    DDF hdr = h.first();
    while (hdr.isstring()) {
        if (!strcasecmp(hdr.name(), "Content-Type")) {
            request.setContentType(hdr.string());
        }
        else {
            request.setResponseHeader(hdr.name(), hdr.string());
        }
        hdr = h.next();
    }

    h = http["redirect"];
    if (h.isstring()) {
        string dest(h.string());
        request.absolutize(dest);
        return make_pair(true, request.sendRedirect(dest.c_str()));
    }

    h = http["response"];
    if (h.isstruct()) {
        const char* data = h["data"].string();
        if (data) {
            // TODO: we should be able to create a custom streambuf to wrap the existing
            // buffer without copying it.
            istringstream s(data);
            return make_pair(true, request.sendResponse(s, h["status"].integer()));
        }
    }

    return make_pair(false, 0L);
}

bool AbstractHandler::getBool(
    const char* name, const SPRequest& request, bool defaultValue, unsigned int type
    ) const
{
    if (type & HANDLER_PROPERTY_REQUEST) {
        const char* param = request.getParameter(name);
        if (param && *param) {
            string_to_bool_translator tr;
            boost::optional<bool> ret = tr.get_value(param);
            if (ret) {
                return ret.get();
            }
        }
    }
    
    if (type & HANDLER_PROPERTY_MAP) {
        if (request.getRequestSettings().first->hasProperty(name)) {
            // The default won't matter since we've already verified the property "exists".
            return request.getRequestSettings().first->getBool(name, defaultValue);
        }
    }

    if (type & HANDLER_PROPERTY_FIXED) {
        return getBool(name, defaultValue);
    }

    return defaultValue;
}

const char* AbstractHandler::getString(
    const char* name, const SPRequest& request, const char* defaultValue, unsigned int type
    ) const
{
    if (type & HANDLER_PROPERTY_REQUEST) {
        const char* param = request.getParameter(name);
        if (param && *param) {
            return param;
        }
    }
    
    if (type & HANDLER_PROPERTY_MAP) {
        if (request.getRequestSettings().first->hasProperty(name)) {
            // The default won't matter since we've already verified the property "exists".
            return request.getRequestSettings().first->getString(name, defaultValue);
        }
    }

    if (type & HANDLER_PROPERTY_FIXED) {
        return getString(name, defaultValue);
    }

    return defaultValue;
}

unsigned int AbstractHandler::getUnsignedInt(
    const char* name, const SPRequest& request, unsigned int defaultValue, unsigned int type) const
{
    if (type & HANDLER_PROPERTY_REQUEST) {
        const char* param = request.getParameter(name);
        if (param && *param) {
            try {
                return boost::lexical_cast<unsigned int>(param);
            }
            catch (const boost::bad_lexical_cast&) {
            }
        }
    }
    
    if (type & HANDLER_PROPERTY_MAP) {
        if (request.getRequestSettings().first->hasProperty(name)) {
            // The default won't matter since we've already verified the property "exists".
            return request.getRequestSettings().first->getUnsignedInt(name, defaultValue);
        }
    }

    if (type & HANDLER_PROPERTY_FIXED) {
        return getUnsignedInt(name, defaultValue);
    }

    return defaultValue;
}

int AbstractHandler::getInt(const char* name, const SPRequest& request, int defaultValue, unsigned int type) const
{
    if (type & HANDLER_PROPERTY_REQUEST) {
        const char* param = request.getParameter(name);
        if (param && *param) {
            try {
                return boost::lexical_cast<unsigned int>(param);
            }
            catch (const boost::bad_lexical_cast&) {
            }
        }
    }
    
    if (type & HANDLER_PROPERTY_MAP) {
        if (request.getRequestSettings().first->hasProperty(name)) {
            // The default won't matter since we've already verified the property "exists".
            return request.getRequestSettings().first->getInt(name, defaultValue);
        }
    }

    if (type & HANDLER_PROPERTY_FIXED) {
        return getInt(name, defaultValue);
    }

    return defaultValue;
}

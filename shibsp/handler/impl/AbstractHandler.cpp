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
#include "handler/LogoutHandler.h"
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
    extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory SAML2ConsumerFactory;
    extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory SAML2LogoutFactory;
    extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory AttributeCheckerFactory;
    extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory MetadataGeneratorFactory;
    extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory StatusHandlerFactory;
    extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory SessionHandlerFactory;

    extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory AdminLogoutInitiatorFactory;
    extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory SAML2LogoutInitiatorFactory;
    extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory LocalLogoutInitiatorFactory;

    extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory SAML2SessionInitiatorFactory;
    extern SHIBSP_DLLLOCAL PluginManager< Handler,string,pair<ptree&,const char*> >::Factory SAMLDSSessionInitiatorFactory;

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
    //conf.HandlerManager.registerFactory(SESSION_HANDLER, SessionHandlerFactory);

    //conf.HandlerManager.registerFactory(SAML20_ASSERTION_CONSUMER_SERVICE, SAML2ConsumerFactory);
 
    conf.HandlerManager.registerFactory(STATUS_HANDLER, StatusHandlerFactory);

    //conf.HandlerManager.registerFactory(SAML20_LOGOUT_HANDLER, SAML2LogoutFactory);

    //conf.HandlerManager.registerFactory(ADMIN_LOGOUT_INITIATOR, AdminLogoutInitiatorFactory);
    //conf.HandlerManager.registerFactory(SAML2_LOGOUT_INITIATOR, SAML2LogoutInitiatorFactory);
    //conf.HandlerManager.registerFactory(LOCAL_LOGOUT_INITIATOR, LocalLogoutInitiatorFactory);

    //conf.HandlerManager.registerFactory(SAML2_SESSION_INITIATOR, SAML2SessionInitiatorFactory);
    //conf.HandlerManager.registerFactory(SAMLDS_SESSION_INITIATOR, SAMLDSSessionInitiatorFactory);
} 

Handler::Handler()
{
}

Handler::~Handler()
{
}

AbstractHandler::AbstractHandler(const ptree& pt, Category& log) : m_log(log) {
    load(pt);
}

AbstractHandler::~AbstractHandler()
{
}


const char* Handler::getEventType() const
{
    return nullptr;
}

void AbstractHandler::cleanRelayState(SPRequest& request) const
{
    const char* mech = request.getRequestSettings().first->getString("relayState");

    int maxRSCookies = 20,purgedRSCookies = 0;
    int maxOSCookies = 20,purgedOSCookies = 0;

    if (mech && !strncmp(mech, "cookie", 6)) {
        mech += 6;
        if (*mech == ':' && isdigit(*(++mech))) {
            maxRSCookies = maxOSCookies = atoi(mech);
            if (maxRSCookies == 0) {
                maxRSCookies = maxOSCookies = 20;
            }
        }
    }

    // Walk the list of cookies backwards by name.
    const map<string,string>& cookies = request.getCookies();
    for (map<string,string>::const_reverse_iterator i = cookies.rbegin(); i != cookies.rend(); ++i) {
        if (boost::starts_with(i->first, "_shibstate_")) {
            if (maxRSCookies > 0) {
                // Keep it, but count it against the limit.
                --maxRSCookies;
            }
            else {
                // We're over the limit, so everything here and older gets cleaned up.
                request.setCookie(i->first.c_str(), nullptr, 0, HTTPResponse::SAMESITE_NONE);
                ++purgedRSCookies;
            }
        }
        else if (boost::starts_with(i->first, "_opensaml_req_")) {
            if (maxOSCookies > 0) {
                // Keep it, but count it against the limit.
                --maxOSCookies;
            }
            else {
                // We're over the limit, so everything here and older gets cleaned up.
                request.setCookie(i->first.c_str(), nullptr, 0, HTTPResponse::SAMESITE_NONE);
                ++purgedOSCookies;
            }
        }
    }

    if (purgedRSCookies > 0)
        m_log.debug(string("purged ") + boost::lexical_cast<string>(purgedRSCookies) + " stale relay state cookie(s) from client");
    if (purgedOSCookies > 0)
        m_log.debug(string("purged ") + boost::lexical_cast<string>(purgedOSCookies) + " stale request correlation cookie(s) from client");
}

void AbstractHandler::preserveRelayState(SPRequest& request, string& relayState) const
{
    // The empty string implies no state to deal with but we need to generate a correlation handle.
    if (relayState.empty()) {
        generateRandomHex(relayState, 4);
        relayState = "corr:" + boost::lexical_cast<string>(time(nullptr)) + '_' + relayState;
        return;
    }

    // No setting means just pass state by value.
    const char* mech = request.getRequestSettings().first->getString("relayState");
    if (!mech || !*mech) {
        return;
    }

    if (!strncmp(mech, "cookie", 6)) {
        // Here we store the state in a cookie and send a fixed
        // value so we can recognize it on the way back.
        if (relayState.find("cookie:") != 0 && relayState.find("ss:") != 0) {
            // Generate a random key for the cookie name instead of the fixed name.
            string rsKey;
            generateRandomHex(rsKey, 4);
            rsKey = boost::lexical_cast<string>(time(nullptr)) + '_' + rsKey;
            string shib_cookie_name = "_shibstate_" + rsKey;
            request.setCookie(shib_cookie_name.c_str(),
                AgentConfig::getConfig().getURLEncoder().encode(relayState.c_str()).c_str(),
                    0, HTTPResponse::SAMESITE_NONE);
            relayState = "cookie:" + rsKey;
        }
    }
    else if (!strncmp(mech, "ss:", 3)) {
        if (relayState.find("cookie:") != 0 && relayState.find("ss:") != 0) {
            mech+=3;
            if (*mech) {
                if (false) {
#ifndef SHIBSP_LITE
                    StorageService* storage = application.getServiceProvider().getStorageService(mech.second);
                    if (storage) {
                        // Use a random key
                        string rsKey;
                        SAMLConfig::getConfig().generateRandomBytes(rsKey,32);
                        rsKey = SAMLArtifact::toHex(rsKey);
                        if (relayState.length() <= storage->getCapabilities().getStringSize()) {
                            if (!storage->createString("RelayState", rsKey.c_str(), relayState.c_str(), time(nullptr) + 600))
                                throw IOException("Collision generating in-memory relay state key.");
                        }
                        else {
                            if (!storage->createText("RelayState", rsKey.c_str(), relayState.c_str(), time(nullptr) + 600))
                                throw IOException("Collision generating in-memory relay state key.");
                        }
                        relayState = string(mech.second-3) + ':' + rsKey;
                    }
                    else {
                        string msg("Storage-backed RelayState with invalid StorageService ID (");
                        msg = msg + mech.second+ ')';
                        log(SPRequest::SPError, msg);
                        relayState.erase();
                    }
#else
                    throw ConfigurationException("Lite version of library cannot be used out of process.");
#endif
                }
                else if (true) {
                    DDF out,in = DDF("set::RelayState").structure();
                    in.addmember("id").string(mech);
                    in.addmember("value").unsafe_string(relayState.c_str());
                    DDFJanitor jin(in),jout(out);
                    out = request.getAgent().getRemotingService()->send(in);
                    if (!out.isstring())
                        throw IOException("StorageService-backed RelayState mechanism did not return a state key.");
                    relayState = string(mech-3) + ':' + out.string();
                }
            }
        }
    }
    else {
        throw ConfigurationException("Unsupported relayState mechanism.");
    }
}

void AbstractHandler::recoverRelayState(SPRequest& request, string& relayState, bool clear) const
{
    // Sentry value that signifies it was only a correlation tool.
    if (boost::starts_with(relayState, "corr:")) {
        relayState.clear();
        return;
    }

    // Look for StorageService-backed state of the form "ss:SSID:key".
    const char* state = relayState.c_str();
    if (strstr(state,"ss:") == state) {
        state += 3;
        const char* key = strchr(state,':');
        if (key) {
            string ssid = relayState.substr(3, key - state);
            key++;
            if (!ssid.empty() && *key) {
                if (false) {
#ifndef SHIBSP_LITE
                    StorageService* storage = conf.getServiceProvider()->getStorageService(ssid.c_str());
                    if (storage) {
                        ssid = key;
                        if (storage->readString("RelayState",ssid.c_str(),&relayState) > 0) {
                            if (clear)
                                storage->deleteString("RelayState",ssid.c_str());
                            request.absolutize(relayState);
                            return;
                        }
                        else if (storage->readText("RelayState",ssid.c_str(),&relayState) > 0) {
                            if (clear)
                                storage->deleteText("RelayState",ssid.c_str());
                            request.absolutize(relayState);
                            return;
                        }
                        else {
                            relayState.erase();
                        }
                    }
                    else {
                        string msg("Storage-backed RelayState with invalid StorageService ID (");
                        msg += ssid + ')';
                        log(SPRequest::SPError, msg);
                        relayState.erase();
                    }
#endif
                }
                else if (true) {
                    DDF out,in = DDF("get::RelayState").structure();
                    in.addmember("id").string(ssid.c_str());
                    in.addmember("key").string(key);
                    in.addmember("clear").integer(clear ? 1 : 0);
                    DDFJanitor jin(in),jout(out);
                    out = request.getAgent().getRemotingService()->send(in);
                    if (!out.isstring()) {
                        m_log.error("StorageService-backed RelayState mechanism did not return a state value.");
                        relayState.erase();
                    }
                    else {
                        relayState = out.string();
                        request.absolutize(relayState);
                        return;
                    }
                }
            }
        }
    }

    // Look for cookie-backed state of the form "cookie:timestamp_key".
    state = relayState.c_str();
    if (strstr(state,"cookie:") == state) {
        state += 7;
        if (*state) {
            // Pull the value from the "relay state" cookie.
            string relay_cookie = string("_shibstate_") + state;
            state = request.getCookie(relay_cookie.c_str());
            if (state && *state) {
                // URL-decode the value.
                char* rscopy = strdup(state);
                AgentConfig::getConfig().getURLEncoder().decode(rscopy);
                relayState = rscopy;
                free(rscopy);
                if (clear) {
                    request.setCookie(relay_cookie.c_str(), nullptr, 0, HTTPResponse::SAMESITE_NONE);
                }
                request.absolutize(relayState);
                return;
            }
        }

        relayState.erase();
    }

    // Check for "default" value (or the old "cookie" value that might come from stale bookmarks).
    if (relayState.empty() || relayState == "default" || relayState == "cookie") {
        relayState = request.getRequestSettings().first->getString("homeURL", "/");
    }

    request.absolutize(relayState);
}

void AbstractHandler::preservePostData(SPRequest& request, const char* relayState) const
{
    if (strcasecmp(request.getMethod(), "POST")) {
        return;
    }

    // No specs mean no save.
    const char* mech = request.getRequestSettings().first->getString("postData");
    if (!mech) {
        m_log.info("postData property not supplied, form data will not be preserved across SSO");
        return;
    }

    DDF postData = getPostData(request);
    if (postData.isnull())
        return;

    if (strstr(mech, "ss:") == mech) {
        mech+=3;
        if (!*mech) {
            postData.destroy();
            throw ConfigurationException("Unsupported postData mechanism.");
        }

        string postkey;
        if (false) {
            DDFJanitor postjan(postData);
#ifndef SHIBSP_LITE
            StorageService* storage = application.getServiceProvider().getStorageService(mech.second);
            if (storage) {
                // Use a random key
                string rsKey;
                SAMLConfig::getConfig().generateRandomBytes(rsKey, 32);
                rsKey = SAMLArtifact::toHex(rsKey);
                ostringstream out;
                out << postData;
                if (!storage->createText("PostData", rsKey.c_str(), out.str().c_str(), time(nullptr) + 600))
                    throw IOException("Attempted to insert duplicate storage key.");
                postkey = string(mech.second-3) + ':' + rsKey;
            }
            else {
                m_log.error("storage-backed PostData mechanism with invalid StorageService ID (%s)", mech.second);
            }
#else
            throw ConfigurationException("Lite version of library cannot be used out of process.");
#endif
        }
        else if (true) {
            DDF out,in = DDF("set::PostData").structure();
            DDFJanitor jin(in),jout(out);
            in.addmember("id").string(mech);
            in.add(postData);
            out = request.getAgent().getRemotingService()->send(in);
            if (!out.isstring())
                throw IOException("StorageService-backed PostData mechanism did not return a state key.");
            postkey = string(mech-3) + ':' + out.string();
        }

        string shib_cookie = getPostCookieName(request, relayState);

        // Purge any cookies in excess of 25.
        int maxCookies = 20,purgedCookies = 0;

        // Walk the list of cookies backwards by name.
        const map<string,string>& cookies = request.getCookies();
        for (map<string,string>::const_reverse_iterator i = cookies.rbegin(); i != cookies.rend(); ++i) {
            // Process post data cookies only.
            if (boost::starts_with(i->first, "_shibpost_")) {
                if (maxCookies > 0) {
                    // Keep it, but count it against the limit.
                    --maxCookies;
                }
                else {
                    // We're over the limit, so everything here and older gets cleaned up.
                    request.setCookie(i->first.c_str(), nullptr, 0, HTTPResponse::SAMESITE_NONE);
                    ++purgedCookies;
                }
            }
        }

        if (purgedCookies > 0)
            m_log.debug(string("purged ") + boost::lexical_cast<string>(purgedCookies) + " stale POST preservation cookie(s) from client");

        // Set a cookie with key info.
        request.setCookie(shib_cookie.c_str(), postkey.c_str(), 0, HTTPResponse::SAMESITE_NONE);
    }
    else {
        postData.destroy();
        throw ConfigurationException("Unsupported postData mechanism.");
    }
}

DDF AbstractHandler::recoverPostData(SPRequest& request, const char* relayState) const
{
    string shib_cookie = getPostCookieName(request, relayState);

    // First we need the post recovery cookie.
    const char* cookie = request.getCookie(shib_cookie.c_str());
    if (!cookie || !*cookie)
        return DDF();

    // Clear the cookie.
    request.setCookie(shib_cookie.c_str(), nullptr, 0, HTTPResponse::SAMESITE_NONE);

    // Look for StorageService-backed state of the form "ss:SSID:key".
    const char* state = cookie;
    if (strstr(state, "ss:") == state) {
        state += 3;
        const char* key = strchr(state, ':');
        if (key) {
            string ssid = string(cookie).substr(3, key - state);
            key++;
            if (!ssid.empty() && *key) {
                if (false) {
#ifndef SHIBSP_LITE
                    StorageService* storage = conf.getServiceProvider()->getStorageService(ssid.c_str());
                    if (storage) {
                        if (storage->readText("PostData", key, &ssid) > 0) {
                            storage->deleteText("PostData", key);
                            istringstream inret(ssid);
                            DDF ret;
                            inret >> ret;
                            return ret;
                        }
                        else {
                            m_log.error("failed to recover form post data using key (%s)", key);
                        }
                    }
                    else {
                        m_log.error("storage-backed PostData with invalid StorageService ID (%s)", ssid.c_str());
                    }
#endif
                }
                else if (true) {
                    DDF in = DDF("get::PostData").structure();
                    DDFJanitor jin(in);
                    in.addmember("id").string(ssid.c_str());
                    in.addmember("key").string(key);
                    DDF out = request.getAgent().getRemotingService()->send(in);
                    if (out.islist())
                        return out;
                    out.destroy();
                    m_log.error("storageService-backed PostData mechanism did not return preserved data.");
                }
            }
        }
    }
    return DDF();
}

long AbstractHandler::sendPostResponse(HTTPResponse& httpResponse, const char* url, DDF& postData) const
{
    HTTPResponse::sanitizeURL(url);

    // TODO: this will require handling by the hub.

    /*
    const PropertySet* props=application.getPropertySet("Sessions");
    pair<bool,const char*> postTemplate = props ? props->getString("postTemplate") : pair<bool,const char*>(true,nullptr);
    if (!postTemplate.first)
        postTemplate.second = "postTemplate.html";

    string fname(postTemplate.second);
    ifstream infile(AgentConfig::getConfig().getPathResolver().resolve(fname, PathResolver::SHIBSP_CFG_FILE).c_str());
    if (!infile)
        throw ConfigurationException("Unable to access HTML template ($1).", params(1, fname.c_str()));
    TemplateParameters respParam;
    respParam.m_map["action"] = url;

    // Load the parameters into objects for the template.
    multimap<string,string>& collection = respParam.m_collectionMap["PostedData"];
    DDF param = postData.first();
    while (!param.isnull()) {
        collection.insert(pair<const string,string>(param.name(), (param.string() ? param.string() : "")));
        param = postData.next();
    }

    stringstream str;
    XMLToolingConfig::getConfig().getTemplateEngine()->run(infile, str, respParam);

    pair<bool,bool> postExpire = props ? props->getBool("postExpire") : make_pair(false,false);

    httpResponse.setContentType("text/html");
    if (!postExpire.first || postExpire.second) {
        httpResponse.setResponseHeader("Expires", "Wed, 01 Jan 1997 12:00:00 GMT");
        httpResponse.setResponseHeader("Cache-Control", "no-cache, no-store, must-revalidate, private, max-age=0");
        httpResponse.setResponseHeader("Pragma", "no-cache");
    }
    return httpResponse.sendResponse(str);
    */
   return 0;
}

string AbstractHandler::getPostCookieName(const SPRequest& request, const char* relayState) const
{
    // Decorates the name of the cookie with the relay state key, if any.
    // Doing so gives a better assurance that the recovered data really
    // belongs to the relayed request.
    if (strstr(relayState, "cookie:") == relayState) {
        return string("_shibpost_") + (relayState + 7);
    }
    else if (strstr(relayState, "ss:") == relayState) {
        const char* pch = strchr(relayState + 3, ':');
        if (pch)
            return string("_shibpost_") + (pch + 1);
    }
    return request.getCookieName("_shibpost_");
}

DDF AbstractHandler::getPostData(const SPRequest& request) const
{
    string contentType = request.getContentType();
    if (contentType.find("application/x-www-form-urlencoded") != string::npos) {
        unsigned int plimit = request.getRequestSettings().first->getUnsignedInt("postLimit", 1024 * 1024);
        if (plimit == 0 || request.getContentLength() <= plimit) {
            CGIParser cgi(request);
            pair<CGIParser::walker,CGIParser::walker> params = cgi.getParameters(nullptr);
            if (params.first == params.second)
                return DDF("parameters").list();
            DDF child;
            DDF ret = DDF("parameters").list();
            for (; params.first != params.second; ++params.first) {
                if (!params.first->first.empty()) {
                    child = DDF(params.first->first.c_str()).unsafe_string(params.first->second);
                    ret.add(child);
                }
            }
            return ret;
        }
        else {
            m_log.warn("POST limit exceeded, ignoring %d bytes of posted data", request.getContentLength());
        }
    }
    else {
        m_log.info("ignoring POST data with non-standard encoding (%s)", contentType.c_str());
    }
    return DDF();
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
            if (ret.has_value()) {
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

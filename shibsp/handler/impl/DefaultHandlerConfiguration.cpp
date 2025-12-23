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
 * handler/impl/DefaultHandlerConfiguration.cpp
 * 
 * Default ptree-based HandlerConfiguration implementation.
 */


#include "internal.h"

#include "exceptions.h"
#include "AgentConfig.h"
#include "handler/Handler.h"
#include "handler/HandlerConfiguration.h"
#include "logging/Category.h"
#include "remoting/ddf.h"

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>

#include <map>
#include <string>
#include <stdexcept>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace {

    class DefaultHandlerConfiguration : public virtual HandlerConfiguration {
    public:
        DefaultHandlerConfiguration(const char* pathname);
        ~DefaultHandlerConfiguration() {}

        const Handler* getAbsoluteHandler(SPRequest& request) const;
        const Handler* getRelativeHandler(const char* path) const;
        const Handler& getSessionInitiator() const;
        DDF getTokenConsumerInfo(const char* handlerURL=nullptr) const;

    private:
        ptree m_pt;
        map<string,unique_ptr<Handler>> m_absoluteHandlerMap;
        map<string,unique_ptr<Handler>> m_relativeHandlerMap;
        const Handler* m_sessionInitiator;
        DDF m_tokenConsumerConfig;
    };

    static const char TYPE_PROP_NAME[] = "type";
    static const char LEGACY_BINDING_PROP_NAME[] = "legacyBinding";
};

HandlerConfiguration::HandlerConfiguration() {}

HandlerConfiguration::~HandlerConfiguration() {}

DefaultHandlerConfiguration::DefaultHandlerConfiguration(const char* pathname)
    : m_sessionInitiator(nullptr), m_tokenConsumerConfig("response_url")
{
    ini_parser::read_ini(pathname, m_pt);

    m_tokenConsumerConfig.list();
    
    Category& log = Category::getInstance(SHIBSP_LOGCAT ".HandlerConfiguration");

    for (auto& child : m_pt) {
        if (child.first.empty()) {
            log.warn("config (%s) skipping handler with no path set", pathname);
            continue;
        }
        
        boost::optional<string> type = child.second.get_optional<string>(TYPE_PROP_NAME);
        if (!type) {
            log.warn("config (%s) skipping handler at %s with no type property", pathname, child.first.c_str());
            continue;
        }
        else if (*type == SESSION_INITIATOR_HANDLER && m_sessionInitiator) {
            throw ConfigurationException("Multiple SessionInitiator handlers were configured, only one is permitted.");
        }

        bool relative = false;
        string handlerPath(child.first);
        if (handlerPath.front() != '/') {
            relative = true;
            handlerPath = '/' + handlerPath;
        }

        // Handlers have to know their own path in some cases, so that has to be injected into the
        // factory method, as ptrees don't know their own name unfortunately, thus the section header
        // value is lost when passing the section tree itself in.
        unique_ptr<Handler> handler(AgentConfig::getConfig().HandlerManager.newPlugin(
            type.get(), pair<ptree&,const char*>(child.second, handlerPath.c_str()), false));
            
        if (relative) {
            // Save off a single SessionInitiator.
            if (*type == SESSION_INITIATOR_HANDLER) {
                m_sessionInitiator = handler.get();
            }
            else if (*type == TOKEN_CONSUMER_HANDLER) {
                DDF tokenConsumer(nullptr);
                // String value of DDF is the handler location.
                tokenConsumer.string(handlerPath);
                m_tokenConsumerConfig.add(tokenConsumer);

                // Check for legacy "binding" value to carry along with path as the name of the node.
                boost::optional<string> legacyBinding = child.second.get_optional<string>(LEGACY_BINDING_PROP_NAME);
                if (legacyBinding) {
                    tokenConsumer.name(legacyBinding.get());
                }
            }
            m_relativeHandlerMap[handlerPath] = std::move(handler);
        }
        else if (type.get() != PASSTHROUGH_HANDLER) {
            throw ConfigurationException("Only Passtrhough handlers may be absolute.");
        }
        else {
            m_absoluteHandlerMap[handlerPath] = std::move(handler);
        }
        log.info("config (%s) installed %s %s handler at %s", pathname, relative ? "relative" : "absolute",
            type.get().c_str(), handlerPath.c_str());
    }

    // If a single token consumer with no binding label is installed, convert list to a string node.
    if (m_tokenConsumerConfig.integer() == 1 && !m_tokenConsumerConfig.first().name()) {
        DDF singleEndpoint("response_url");
        singleEndpoint.string(m_tokenConsumerConfig.first().string());
        m_tokenConsumerConfig.destroy();
        m_tokenConsumerConfig = singleEndpoint;
    }
}

const Handler* DefaultHandlerConfiguration::getAbsoluteHandler(SPRequest& request) const
{
    // Check for a request URI (minus query string) that matches an absolute handler.
    string wrapped_uri(request.getRequestURI());
    wrapped_uri = wrapped_uri.substr(0, wrapped_uri.find(';'));
    const auto& mapping = m_absoluteHandlerMap.find(wrapped_uri.substr(0, wrapped_uri.find('?')));
    if (mapping != m_absoluteHandlerMap.end()) {
        return mapping->second.get();
    }

    return nullptr;
}

const Handler* DefaultHandlerConfiguration::getRelativeHandler(const char* path) const
{
    if (path) {
        string wrap(path);
        wrap = wrap.substr(0, wrap.find(';'));
        const auto& mapping = m_relativeHandlerMap.find(wrap.substr(0, wrap.find('?')));
        if (mapping != m_relativeHandlerMap.end()) {
            return mapping->second.get();
        }
    }
    return nullptr;
}

const Handler& DefaultHandlerConfiguration::getSessionInitiator() const
{
    if (m_sessionInitiator) {
        return *m_sessionInitiator;
    }
    throw ConfigurationException("No SessionInitiator configured.");
}

DDF DefaultHandlerConfiguration::getTokenConsumerInfo(const char* handlerURL) const
{
    DDF dup = m_tokenConsumerConfig.copy();

    if (handlerURL) {
        if (dup.islist()) {
            DDF endpoint = dup.first();
            while (!endpoint.isnull()) {
                string path(handlerURL);
                path += endpoint.string();
                endpoint.string(path.c_str());
                endpoint = dup.next();
            }
        }
        else if (dup.isstring()) {
            string path(handlerURL);
            path += dup.string();
            dup.string(path.c_str());
        }
    }

    return dup;
}

unique_ptr<HandlerConfiguration> HandlerConfiguration::newHandlerConfiguration(const char* pathname)
{
    return unique_ptr<HandlerConfiguration>(new DefaultHandlerConfiguration(pathname));
}

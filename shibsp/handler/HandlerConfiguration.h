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
 * @file shibsp/handler/HandlerConfiguration.h
 * 
 * Interface to the set of handlers that are exposed by an agent at specific path(s).
 */

#ifndef __shibsp_handlerconfig_h__
#define __shibsp_handlerconfig_h__

#include <shibsp/base.h>

#include <memory>
#include <utility>

namespace shibsp {

    class SHIBSP_API Handler;
    class SHIBSP_API DDF;

    /**
     * Interface to the set of handlers that are exposed by an agent at specific path(s).
     */
    class SHIBSP_API HandlerConfiguration
    {
        MAKE_NONCOPYABLE(HandlerConfiguration);
    protected:
        HandlerConfiguration();

    public:
        virtual ~HandlerConfiguration();

        /**
         * Gets the Handler installed at an absolute path if one is installed.
         * 
         * @param path absolute path to map to a Handler
         * 
         * @return the Handler configured at the request's location, or null
         */
        virtual const Handler* getAbsoluteHandler(SPRequest& request) const=0;

        /**
         * Gets the Handler installed at a particular path, relative to a "base" URL used for
         * triggering all Handlers.
         * 
         * @param path relative path to map to a Handler
         * 
         * @return the Handler configured at the supplied location, or null
         */
        virtual const Handler* getRelativeHandler(const char* path) const=0;

        /**
         * Gets the Handler used for SSO session initiation.
         * 
         * <p>Only one such Handler may be defined within a configuration and one
         * must be defined.</p>
         * 
         * @return the session initiator Handler
         */
        virtual const Handler& getSessionInitiator() const=0;

        /**
         * Gets a DDF object suitable for adding into session initiator requests to the hub.
         * 
         * <p>This is a newly allocated list that must be freed by the caller.</p>
         * 
         * <p>This is required to support the communication of the possible response
         * paths for the agent to the hub when formulating SSO protocol requests, and encapsulates
         * a number of technical details that may be required, insulating the handlers from
         * dealing with this iinformation.</p>
         * 
         * <p>Legacy configurations designed to avoid externally visible changes may continue
         * to operate multiple handlers to support different SSO bindings or patterns, while
         * newer deployments should avoid this practice and stick to a single location. The
         * "meta-information" required to support this legacy practice will be embedded within
         * the structure returned.</p>
         * 
         * @param handlerURL the handler base URL with which to prefix the token consumer
         *  endpoint paths
         * 
         * @return new DDF object encapsulating token consumer handler metadata
         */
        virtual DDF getTokenConsumerInfo(const char* handlerURL=nullptr) const=0;

        /**
         * Create a new HandlerConfiguration based on the supplied configuration file.
         * 
         * @param pathname  configuration file
         * 
         * @return the corresponding HandlerConfiguration
         */
        static std::unique_ptr<HandlerConfiguration> newHandlerConfiguration(const char* pathname);
    };

};

#endif /* __shibsp_handlerconfig_h__ */

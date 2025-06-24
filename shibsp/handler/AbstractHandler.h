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
 * @file shibsp/handler/AbstractHandler.h
 * 
 * Base class for handlers based on a DOMPropertySet.
 */

#ifndef __shibsp_abshandler_h__
#define __shibsp_abshandler_h__

#include <shibsp/handler/Handler.h>
#include <shibsp/remoting/ddf.h>
#include <shibsp/util/BoostPropertySet.h>

#include <string>
#include <vector>
#include <boost/property_tree/ptree_fwd.hpp>

namespace shibsp {

    class SHIBSP_API SPRequest;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    /**
     * Base class for handlers based on a BoostPropertySet.
     * 
     * TODO: Most of this probably is replaced/removed with hub operations.
     */
    class SHIBSP_API AbstractHandler : public virtual Handler, public virtual BoostPropertySet
    {
    protected:
        /**
         * Constructor.
         * 
         * @param pt    root of handler configuration
         */
        AbstractHandler(const boost::property_tree::ptree& pt);

        /**
         * Wrap a request for remoting to hub.
         * 
         * @param request the request to remote
         * @param headers names of request headers to remote
         * 
         * @return wrapped structure to add to remoted data
         */
        virtual DDF wrapRequest(
            const SPRequest& request, const std::vector<std::string>& headers, bool sendBody=true
            ) const;

        /**
         * Unwrap a response from the hub and play back to user agent.
         * 
         * @param request request to playback response into
         * @param wrappedResponse wrapped response data
         * 
         * @return result of response playback to return from handler
         */
        virtual std::pair<bool,long> unwrapResponse(SPRequest& request, DDF& wrappedResponse) const;

        /**
         * Bitmask of property sources to read from:
         * (request query parameter, request mapper, fixed handler property).
         */
        enum PropertySourceTypes {
            HANDLER_PROPERTY_REQUEST = 1,
            HANDLER_PROPERTY_MAP = 2,
            HANDLER_PROPERTY_FIXED = 4,
            HANDLER_PROPERTY_ALL = 255
        };

        using BoostPropertySet::getBool;
        using BoostPropertySet::getString;
        using BoostPropertySet::getUnsignedInt;
        using BoostPropertySet::getInt;

        /**
         * Returns a boolean-valued property.
         * 
         * @param name          property name
         * @param request       reference to incoming request
         * @param defaultValue  value to return if property is not set
         * @param type          bitmask of property sources to use
         * @return property value (or the default)
         */
        bool getBool(
            const char* name, const SPRequest& request, bool defaultValue, unsigned int type=HANDLER_PROPERTY_ALL
            ) const;

        /**
         * Returns a string-valued property.
         * 
         * @param name          property name
         * @param request       reference to incoming request
         * @param defaultValue  value to return if property is not set
         * @param type          bitmask of property sources to use
         * @return property value (or the default)
         */
        const char* getString(
            const char* name, const SPRequest& request, const char* defaultValue=nullptr, unsigned int type=HANDLER_PROPERTY_ALL
            ) const;

        /**
         * Returns an unsigned integer-valued property.
         * 
         * @param name          property name
         * @param request       reference to incoming request
         * @param defaultValue  value to return if property is not set
         * @param type          bitmask of property sources to use
         * @return property value (or the default)
         */
        unsigned int getUnsignedInt(
            const char* name, const SPRequest& request, unsigned int defaultValue, unsigned int type=HANDLER_PROPERTY_ALL
            ) const;

        /**
         * Returns an integer-valued property.
         * 
         * @param name          property name
         * @param request       reference to incoming request
         * @param defaultValue  value to return if property is not set
         * @param type          bitmask of property sources to use
         * @return property value (or the default)
         */
        int getInt(
            const char* name, const SPRequest& request, int defaultValue, unsigned int type=HANDLER_PROPERTY_ALL
            ) const;

    public:
        virtual ~AbstractHandler();

    private:
        std::string getPostCookieName(const SPRequest& request, const char* relayState) const;
        DDF getPostData(const SPRequest& request) const;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_abshandler_h__ */

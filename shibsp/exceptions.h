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
 * @file shibsp/exceptions.h
 * 
 * Exception classes.
 */
 
#ifndef __shibsp_exceptions_h__
#define __shibsp_exceptions_h__

#include <shibsp/base.h>
#include <shibsp/logging/Priority.h>

#include <exception>
#include <string>
#include <unordered_map>

/**
 * Declares an SP exception subclass.
 * 
 * @param name      the exception class
 * @param linkage   linkage specification for class
 * @param base      the base class
 */
#define DECL_SHIBSP_EXCEPTION(name,linkage,base) \
    class linkage name : public base { \
    public: \
        name(const char* msg=nullptr) : base(msg) {} \
        name(const std::string& msg) : base(msg) {} \
        virtual ~name() noexcept {} \
    }

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 4251 )
#endif

    class SHIBSP_API SPRequest;

    /**
     * Base exception class, supports attaching additional data for error handling.
     */
    class SHIBSP_EXCEPTIONAPI(SHIBSP_API) AgentException : public std::exception
    {
    public:
        virtual ~AgentException() noexcept;

        /**
         * Constructs an exception using a message.
         * 
         * @param msg   error message
         */
        AgentException(const char* msg=nullptr);

        /**
         * Constructs an exception using a message.
         * 
         * @param msg   error message
         */
        AgentException(const std::string& msg);

        /**
         * Returns the error message, after processing any parameter references.
         * 
         * @return  the processed message
         */
        const char* what() const noexcept;

        /**
         * Gets the HTTP status code for the error condition.
         * 
         * @return status code
         */
        long getStatusCode() const noexcept;

        /**
         * Sets the HTTP status code for the error condition if not the default of 500.
         * 
         * @param code status code
         */
        void setStatusCode(long code) noexcept;

        /**
         * Gets the properties attached to this exception.
         * 
         * @return property map
         */
        const std::unordered_map<std::string,std::string>& getProperties() const noexcept;

        /**
         * Gets a specific property attached to this exception.
         * 
         * @param name property name
         * 
         * @return property value or null
         */
        const char* getProperty(const char* name) const noexcept;

        /**
         * Attach a set of named properties to the exception.
         * 
         * <p>Property data MAY be passed along to error handling resources and/or be
         * visible in the client, so sensitive data should not be included.</p>
         * 
         * @param params properties to attach
         */
        void addProperties(const std::unordered_map<std::string,std::string>& props);

        /**
         * Attach a single named property.
         * 
         * <p>Property data MAY be passed along to error handling resources and/or be
         * visible in the client, so sensitive data should not be included.</p>
         * 
         * @param name  the property name
         * @param value the property value
         */
        void addProperty(const char* name, const char* value);

        /**
         * Returns a set of query string name/value pairs, URL-encoded, representing the
         * exception's type, message, and parameters.
         *
         * @return  the query string representation
         */
        std::string toQueryString() const;

        /**
         * Log an error through this request using the exception properties as input.
         * 
         * @param request SP request
         * @param priority logging level
         */
        void log(const SPRequest& request, Priority::Value priority=Priority::SHIB_ERROR) const;

        // Defined properties.
        static const char HANDLER_TYPE_PROP_NAME[];
        static const char EVENT_PROP_NAME[];
        static const char TARGET_PROP_NAME[];

    private:
        long m_status;
        std::string m_msg;
        std::unordered_map<std::string,std::string> m_props;
    };

    DECL_SHIBSP_EXCEPTION(AttributeException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),shibsp::AgentException);
    DECL_SHIBSP_EXCEPTION(ConfigurationException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),shibsp::AgentException);
    DECL_SHIBSP_EXCEPTION(IOException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),shibsp::AgentException);
    DECL_SHIBSP_EXCEPTION(RemotingException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),shibsp::AgentException);
    DECL_SHIBSP_EXCEPTION(OperationException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),shibsp::RemotingException);
    DECL_SHIBSP_EXCEPTION(SessionException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),shibsp::AgentException);
    DECL_SHIBSP_EXCEPTION(SessionValidationException,SHIBSP_EXCEPTIONAPI(SHIBSP_API),shibsp::SessionException);

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_exceptions_h__ */

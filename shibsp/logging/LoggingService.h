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
 * @file shibsp/logging/LoggingService.h
 *
 * Logging service abstracting configuration and output of log messages.
 */

#ifndef __shibsp_logging_h__
#define __shibsp_logging_h__

#include <shibsp/logging/Category.h>

namespace shibsp {

     /**
     * Interface to a logging service.
     *
     * Logging services expose a simple API to obtain Category instances to log
     * messages. Applications interact with this service by obtaining Category objects
     * and using them to log messages.
     */
    class SHIBSP_API LoggingService
    {
        MAKE_NONCOPYABLE(LoggingService);
    protected:
        LoggingService();
    public:
        virtual ~LoggingService();

        static const char LOGGING_TYPE_PROP_PATH[];

        /**
         * Initializes the designated logging service.
         */
        virtual bool init()=0;

        /**
         * Terminates the designated logging service.
         */
        virtual void term()=0;

        /**
         * Retrieves an instance of a logging Category of the specified name (empty is permitted).
         * 
         * The object may (but need not be) shared and is owned by the logging service. Its priority
         * will be set based on the underlying configuration of this service and is immutable.
         * 
         * @param name category name
         */
        virtual Category& getCategory(const std::string& name)=0;
    };

    /**
     * Registers LoggingService classes into the runtime.
     */
    void SHIBSP_API registerLoggingServices();

    /** Logging to the console. */
    #define CONSOLE_LOGGING_SERVICE     "console"

    /** Logging to a file. */
    #define FILE_LOGGING_SERVICE     "file"

    /** Logging to the syslog API. */
    #define SYSLOG_LOGGING_SERVICE      "syslog"

    /** Logging to the Windows Event Log. */
    #define WINDOWS_LOGGING_SERVICE     "windows"
};

#endif /* __shibsp_logging_h__ */

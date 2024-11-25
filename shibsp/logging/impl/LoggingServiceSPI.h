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
 * shibsp/logging/LoggingServiceSPI.h
 *
 * Logging service abstracting configuration and output of log messages.
 */

#ifndef __shibsp_loggingspi_h__
#define __shibsp_loggingspi_h__

#include <shibsp/logging/Category.h>

namespace shibsp {

     /**
     * Interface to a logging service implementation.
     *
     * Logging service implementations expose a simple API to output log
     * messages and are the "internal" portion of a LoggingService.
     */
    class SHIBSP_API LoggingServiceSPI
    {
        MAKE_NONCOPYABLE(LoggingServiceSPI);
    protected:
        LoggingServiceSPI();
    public:
        virtual ~LoggingServiceSPI();

        /**
         * Initializes the designated logging service.
         */
        virtual bool init()=0;

        /**
         * Terminates the designated logging service.
         */
        virtual bool term()=0;

        /**
         * Outputs a logging message in whatever manner is defined by the underlying implementation.
         * 
         * @param category logging category
         * @param message logging message
         */
        virtual void outputMessage(const Category& category, const std::string& message)=0;

        /**
         * Outputs a logging message in whatever manner is defined by the underlying implementation.
         * 
         * @param category logging category
         * @param message logging message
         */
        virtual void outputMessage(const Category& category, const char* message)=0;
    };

};

#endif /* __shibsp_loggingspi_h__ */

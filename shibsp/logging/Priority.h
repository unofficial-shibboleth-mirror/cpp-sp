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
 * @file shibsp/logging/Priority.h
 *
 * Constrained set of logging levels.
 */


#ifndef __shibsp_logging_priority_h__
#define __shibsp_logging_priority_h__

#include <shibsp/base.h>

#include <string>

namespace shibsp {

    /**
     * Enumerates levels of logging we support.
     */
    class SHIBSP_API Priority {
        public:

        /**
         * Predefined Levels of Priorities.
         */
        enum PriorityLevel {
            SHIB_CRIT   = 0,
            SHIB_ERROR  = 100,
            SHIB_WARN   = 200,
            SHIB_INFO   = 300,
            SHIB_DEBUG  = 400,
            SHIB_NOTSET = 500
        };

        /**
         * The type of Priority Values.
         */
        typedef int Value;

        /**
         * Returns the name of the given priority value.
         * 
         * Currently, if the value is not one of the PriorityLevel values,
         * the method returns the name of the largest priority smaller 
         * the given value.
         * 
         * @param priority the numeric value of the priority.
         * @returns a string representing the name of the priority.
         */
        static const std::string& getPriorityName(int priority) throw();
	
        /**
         * Returns the value of the given priority name.
         * 
         * This can be either one of SHIB_CRIT ... SHIB_NOTSET or a 
         * decimal string representation of the value, e.g. '700' for SHIB_DEBUG.
         * 
         * @param priorityName the string containing the the of the priority
         * @return the value corresponding with the priority name
         * 
         * @throw std::invalid_argument if the priorityName does not 
         * correspond with a known Priority name or a number
         */
        static Value getPriorityValue(const std::string& priorityName);
    };
}

#endif // __shibsp_logging_priority_h__

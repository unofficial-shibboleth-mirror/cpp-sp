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

#ifndef __shibsp_logging_category_h__
#define __shibsp_logging_category_h__

#include <shibsp/logging/Priority.h>

#include <map>
#include <vector>
#include <cstdarg>
#include <stdexcept>

namespace shibsp {

    /**
     * This is the central class in the logging API, but is not a fully caoable
     * port of a hierarchical logging system that allows differentiation of logging
     * levels by category. This is merely a porting convenience and to potentially
     * allow for that in the future.
     */   
    class SHIBSP_API Category {
        MAKE_NONCOPYABLE(Category);
    public:
        /**
         * Instantiate a Category with name <code>name</code>. This
         * method does not set priority of the category which is by
         * default <code>Priority::NOTSET</code>.
         * 
         * @param name The name of the category to retrieve.
         */
        static Category& getInstance(const std::string& name);
            
        /**
         * Destructor for Category.
         */
        virtual ~Category();
        
        /**
         * Return the category name.
         * 
         * @returns The category name.
         */       
        virtual const std::string& getName() const;
        
        /**
         * Set the priority of this Category.
         * 
         * @param priority The priority to set. Use Priority::NOTSET to let 
         * the category use its parents priority as effective priority.
         * 
         * @exception std::invalid_argument if the caller tries to set
         * Priority::NOTSET on the Root Category.
         */
        virtual void setPriority(Priority::Value priority);

        /**
         * Returns the assigned Priority, if any, for this Category.
         * 
         * @return Priority - the assigned Priority, can be Priority::NOTSET
         */
        virtual Priority::Value getPriority() const;

        /** 
         * Returns true if the priority of the Category is equal to
         * or higher than given priority.
         * 
         * @param priority The priority to compare with.
         * @returns whether logging is enable for this priority.
         */
        virtual bool isPriorityEnabled(Priority::Value priority) const;
        
        /** 
         * Log a message with the specified priority.
         * 
         * @param priority The priority of this log message.
         * @param stringFormat Format specifier for the string to write 
         * in the log file.
         * @param ... The arguments for stringFormat 
         */  
        virtual void log(Priority::Value priority, const char* stringFormat, ...) throw();

        /** 
         * Log a message with the specified priority.
         * @param priority The priority of this log message.
         * @param message string to write in the log file
         */  
        virtual void log(Priority::Value priority, const std::string& message) throw();
        
        /** 
         * Log a message with the specified priority.
         * 
         * @param priority The priority of this log message.
         * @param stringFormat Format specifier for the string to write
         * in the log file.
         * @param va The arguments for stringFormat.
         */  
        virtual void logva(Priority::Value priority, const char* stringFormat, va_list va) throw();
        
        /** 
         * Log a message with debug priority.
         * @param stringFormat Format specifier for the string to write 
         * in the log file.
         * @param ... The arguments for stringFormat 
         */  
        void debug(const char* stringFormat, ...) throw();

        /** 
         * Log a message with debug priority.
         * @param message string to write in the log file
         */  
        void debug(const std::string& message) throw();

        /**
         * Return true if the Category will log messages with priority SHIB_DEBUG.
         * 
         * @returns Whether the Category will log.
         */ 
        inline bool isDebugEnabled() const throw() { 
            return isPriorityEnabled(Priority::SHIB_DEBUG);
        };
        
        /** 
         * Log a message with info priority.
         * 
         * @param stringFormat Format specifier for the string to write 
         * in the log file.
         * @param ... The arguments for stringFormat 
         */  
        void info(const char* stringFormat, ...) throw();

        /** 
         * Log a message with info priority.
         * 
         * @param message string to write in the log file
         */  
        void info(const std::string& message) throw();

        /**
         * Return true if the Category will log messages with priority SHIB_INFO.
         * 
         * @returns Whether the Category will log.
         */ 
        inline bool isInfoEnabled() const throw() { 
            return isPriorityEnabled(Priority::SHIB_INFO);
        };
        
        /** 
         * Log a message with warn priority.
         * 
         * @param stringFormat Format specifier for the string to write 
         * in the log file.
         * @param ... The arguments for stringFormat 
         */  
        void warn(const char* stringFormat, ...) throw();

        /** 
         * Log a message with warn priority.
         * 
         * @param message string to write in the log file
         */  
        void warn(const std::string& message) throw();

        /**
         * Return true if the Category will log messages with priority SHIB_WARN.
         * 
         * @returns Whether the Category will log.
         */ 
        inline bool isWarnEnabled() const throw() { 
            return isPriorityEnabled(Priority::SHIB_WARN);
        };
        
        /** 
         * Log a message with error priority.
         * 
         * @param stringFormat Format specifier for the string to write 
         * in the log file.
         * @param ... The arguments for stringFormat 
         */
        void error(const char* stringFormat, ...) throw();

        /** 
         * Log a message with error priority.
         * 
         * @param message string to write in the log file
         */  
        void error(const std::string& message) throw();

        /**
         * Return true if the Category will log messages with priority SHIB_ERROR.
         * 
         * @returns Whether the Category will log.
         */ 
        inline bool isErrorEnabled() const throw() { 
            return isPriorityEnabled(Priority::SHIB_ERROR);
        };

        /** 
         * Log a message with crit priority.
         * 
         * @param stringFormat Format specifier for the string to write 
         * in the log file.
         * @param ... The arguments for stringFormat 
         */  
        void crit(const char* stringFormat, ...) throw();

        /** 
         * Log a message with crit priority.
         * 
         * @param message string to write in the log file
         */  
        void crit(const std::string& message) throw();

        /**
         * Return true if the Category will log messages with priority CRIT.
         * 
         * @returns Whether the Category will log.
         */ 
        inline bool isCritEnabled() const throw() { 
            return isPriorityEnabled(Priority::SHIB_CRIT);
        };

    protected:
        /**
         * Constructor.
         * 
         * @param name the fully qualified name of this Category
         * @param parent the parent of this parent, or NULL for the root 
         * Category
         * @param priority the priority for this Category. Defaults to
         * Priority::SHIB_NOTSET
         */
        Category(const std::string& name, Priority::Value priority = Priority::SHIB_NOTSET);
        
        /** 
         * Unconditionally log a message with the specified priority.
         * 
         * @param priority The priority of this log message
         * @param format formatting string for message
         * @param arguments variable arguments
         */  
        virtual void _logUnconditionally(Priority::Value priority, const char* format, va_list arguments) throw();
        
        /** 
         * Unconditionally log a message with the specified priority.
         * 
         * @param priority The priority of this log message
         * @param message string to write to the log
         */  
        virtual void _logUnconditionally2(Priority::Value priority, const std::string& message) throw();

    private:
        const std::string m_name;
        Priority::Value m_priority;
    };

}
#endif // __shibsp_logging_category_h__

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

#include "AgentConfig.h"
#include "logging/Category.h"
#include "logging/LoggingService.h"
#include "logging/impl/LoggingServiceSPI.h"
#include "logging/impl/StringUtil.h"

using namespace shibsp;

Category& Category::getInstance(const std::string& name) {
    return AgentConfig::getConfig().getLoggingService().getCategory(name);
}

Category::Category(LoggingServiceSPI& spi, const std::string& name, Priority::Value priority)
    : m_spi(spi), m_name(name), m_priority(priority) {
}

Category::~Category() {
}

const std::string& Category::getName() const {
    return m_name; 
}

Priority::Value Category::getPriority() const { 
    return m_priority; 
}

void Category::_logUnconditionally(Priority::Value priority, const char* format, va_list arguments) throw() {
    _logUnconditionally2(priority, StringUtil::vform(format, arguments));
}

void Category::_logUnconditionally2(Priority::Value priority, const std::string& message) throw() {
    m_spi.outputMessage(*this, priority, message);
}

bool Category::isPriorityEnabled(Priority::Value priority) const {
    return m_priority >= priority;
}

void Category::log(Priority::Value priority, const char* stringFormat, ...) throw() { 
    if (isPriorityEnabled(priority)) {
        va_list va;
        va_start(va, stringFormat);
        _logUnconditionally(priority, stringFormat, va);
        va_end(va);
    }
}

void Category::log(Priority::Value priority, const std::string& message) throw() { 
    if (isPriorityEnabled(priority)) {
        _logUnconditionally2(priority, message);
    }
}

void Category::logva(Priority::Value priority, const char* stringFormat, va_list va) throw() { 
    if (isPriorityEnabled(priority)) {
        _logUnconditionally(priority, stringFormat, va);
    }
}

void Category::debug(const char* stringFormat, ...) throw() { 
    if (isPriorityEnabled(Priority::SHIB_DEBUG)) {
        va_list va;
        va_start(va,stringFormat);
        _logUnconditionally(Priority::SHIB_DEBUG, stringFormat, va);
        va_end(va);
    }
}

void Category::debug(const std::string& message) throw() { 
    if (isPriorityEnabled(Priority::SHIB_DEBUG)) {
        _logUnconditionally2(Priority::SHIB_DEBUG, message);
    }
}

void Category::info(const char* stringFormat, ...) throw() { 
    if (isPriorityEnabled(Priority::SHIB_INFO)) {
        va_list va;
        va_start(va,stringFormat);
        _logUnconditionally(Priority::SHIB_INFO, stringFormat, va);
        va_end(va);
    }
}

void Category::info(const std::string& message) throw() { 
    if (isPriorityEnabled(Priority::SHIB_INFO)) {
        _logUnconditionally2(Priority::SHIB_INFO, message);
    }
}

void Category::warn(const char* stringFormat, ...) throw() { 
    if (isPriorityEnabled(Priority::SHIB_WARN)) {
        va_list va;
        va_start(va,stringFormat);
        _logUnconditionally(Priority::SHIB_WARN, stringFormat, va);
        va_end(va);
    }
}

void Category::warn(const std::string& message) throw() { 
    if (isPriorityEnabled(Priority::SHIB_WARN))
        _logUnconditionally2(Priority::SHIB_WARN, message);
}

void Category::error(const char* stringFormat, ...) throw() { 
    if (isPriorityEnabled(Priority::SHIB_ERROR)) {
        va_list va;
        va_start(va,stringFormat);
        _logUnconditionally(Priority::SHIB_ERROR, stringFormat, va);
        va_end(va);
    }
}

void Category::error(const std::string& message) throw() { 
    if (isPriorityEnabled(Priority::SHIB_ERROR)) {
        _logUnconditionally2(Priority::SHIB_ERROR, message);
    }
}

void Category::crit(const char* stringFormat, ...) throw() { 
    if (isPriorityEnabled(Priority::SHIB_CRIT)) {
        va_list va;
        va_start(va,stringFormat);
        _logUnconditionally(Priority::SHIB_CRIT, stringFormat, va);
        va_end(va);
    }
}

void Category::crit(const std::string& message) throw() { 
    if (isPriorityEnabled(Priority::SHIB_CRIT)) {
        _logUnconditionally2(Priority::SHIB_CRIT, message);
    }
}

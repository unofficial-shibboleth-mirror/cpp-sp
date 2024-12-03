/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/**
 * util/ReloadableFile.cpp
 *
 * Base class for file-based configuration.
 */

#include "internal.h"

#include "AgentConfig.h"
#include "logging/Category.h"
#include "util/PathResolver.h"
#include "util/ReloadableFile.h"

#include <sys/types.h>
#include <sys/stat.h>

using namespace boost::property_tree;
using namespace shibsp;
using namespace std;

ReloadableFile::ReloadableFile(const std::string& path, Category& log, bool reloadChanges)
    : m_log(log), m_source(path), m_filestamp(0)
#ifdef HAVE_CXX17
        , m_lock(nullptr)
#elif HAVE_CXX14
        , m_lock(nullptr)
#endif
{
    AgentConfig::getConfig().getPathResolver().resolve(m_source, PathResolver::SHIBSP_CFG_FILE);

    log.info("using path (%s), will %smonitor for changes", m_source.c_str(), reloadChanges ? "" : "not ");

    if (reloadChanges) {
#ifdef HAVE_CXX17
        m_lock.reset(new shared_mutex());
#elif HAVE_CXX14
        m_lock.reset(new shared_timed_mutex());
#endif
    }
}

ReloadableFile::~ReloadableFile()
{
}

const std::string& ReloadableFile::getSource() const
{
    return m_source;
}

time_t ReloadableFile::getLastModified() const
{
    return m_filestamp;
}

bool ReloadableFile::isUpdated() const
{
#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(m_source.c_str(), &stat_buf) != 0) {
        return false;
    }
#else
    struct stat stat_buf;
    if (stat(m_source.c_str(), &stat_buf) != 0) {
        return false;
    }
#endif
    return stat_buf.st_mtime > m_filestamp;
}

void ReloadableFile::updateModificationTime()
{
#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(m_source.c_str(), &stat_buf) == 0) {
#else
    struct stat stat_buf;
    if (stat(m_source.c_str(), &stat_buf) == 0) {
#endif
        updateModificationTime(stat_buf.st_mtime);
    }
}

void ReloadableFile::updateModificationTime(time_t t)
{
    m_filestamp = t;
}

bool ReloadableFile::load()
{
    updateModificationTime();
    return true;
}

void ReloadableFile::lock()
{
    if (m_lock) {
        m_lock->lock();
    }
}

bool ReloadableFile::try_lock()
{
    if (m_lock) {
        return m_lock->try_lock();
    }
}

void ReloadableFile::unlock()
{
    if (m_lock)
        m_lock->unlock();
}

void ReloadableFile::lock_shared()
{
    if (!m_lock) {
        return;
    }

    m_lock->lock_shared();

    // Check if we need to refresh.
    if (!isUpdated()) {
        return;
    }

    m_lock->unlock();
    m_log.info("change detected, attempting reload...");

    if (load()) {
        m_log.info("swapped in new configuration");
    } else {
        m_log.info("new configuration was invalid");
    }

    m_lock->lock_shared();
}

bool ReloadableFile::try_lock_shared()
{
    if (m_lock)
        return m_lock->try_lock_shared();
    else
        return true;
}

void ReloadableFile::unlock_shared()
{
    if (m_lock)
        m_lock->unlock_shared();
}

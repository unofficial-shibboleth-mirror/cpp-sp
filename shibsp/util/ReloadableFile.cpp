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
#include <boost/property_tree/xml_parser.hpp>

using namespace boost::property_tree;
using namespace shibsp;
using namespace std;

namespace {
    // More an experiment than anything but it does encapsulate the conversion.
    struct string_to_bool_translator {
        typedef std::string internal_type;
        typedef bool external_type;

        boost::optional<bool> get_value(const string &s) {
            if (s == "true" || s == "1") {
                return boost::make_optional(true);
            } else if (s == "false" || s == "0") {
                return boost::make_optional(false);
            } else {
                return boost::none;
            }
        }
    };
};

const char ReloadableFile::PATH_PROP_NAME[] = "path";
const char ReloadableFile::RELOAD_CHANGES_PROP_NAME[] = "reloadChanges";

ReloadableFile::ReloadableFile(const ptree& pt, Category& log) : m_root(pt), m_log(log), m_filestamp(0)
#ifdef HAVE_CXX17
        , m_lock(nullptr)
#elif HAVE_CXX14
        , m_lock(nullptr)
#endif
{
    boost::optional<string> path = pt.get_optional<string>(PATH_PROP_NAME);
    if (path) {
        m_source = path.get();
        AgentConfig::getConfig().getPathResolver().resolve(m_source, PathResolver::SHIBSP_CFG_FILE);

        string_to_bool_translator tr;
        bool reloadChanges = pt.get(RELOAD_CHANGES_PROP_NAME, false, tr);
        log.info("using path (%s), will %smonitor for changes", m_source.c_str(), reloadChanges ? "" : "not ");
        if (reloadChanges) {
#ifdef HAVE_CXX17
            m_lock.reset(new shared_mutex());
#elif HAVE_CXX14
            m_lock.reset(new shared_timed_mutex());
#endif
        }
    }
}

ReloadableFile::~ReloadableFile()
{
}

time_t ReloadableFile::getLastModified() const
{
    return m_filestamp;
}

bool ReloadableFile::isUpdated() const
{
    if (m_source.empty()) {
        return false;
    }

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

pair<bool,ptree*> ReloadableFile::load()
{
    if (m_source.empty()) {
        m_log.debug("loading inline configuration...");
        // Data comes from the tree we were handed.
        // Because property trees work differently from an XML DOM,
        // we return the actual root, and not the first child as before
        // so the caller can interrogate the name of the child tree to
        // ensure it's as expected.
        // The const_cast is safe because the flag is false,
        // preventing the caller from retaining ownership.
        return make_pair(false, const_cast<ptree*>(&m_root));
    }

    try {
        unique_ptr<ptree> newtree = unique_ptr<ptree>(new ptree());
        xml_parser::read_xml(m_source, *newtree, xml_parser::no_comments|xml_parser::trim_whitespace);
        return make_pair(true, newtree.release());
    } catch (const bad_alloc& e) {
        m_log.crit("out of memory parsing XML configuration (%s)", m_source.c_str());
    } catch (const xml_parser_error& e) {
        m_log.error("failed to process XML configuration (%s): %s", m_source.c_str(), e.what());
    }
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

    // TODO: maybe a second mutex could guard the reload operation so > 1 thread doesn't try it?

    // The result is handled entirely by the subclass so is ignored here.
    // The original root tree is purely a means of communicating the object
    // from the c'tor over to the load method for the inline case, at first load.
    try {
        load();
    } catch (...) {
        // Shouldn't happen but ensures we generally will acquire the lock before returning.
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

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
 * @file ReloadableXMLFile.cpp
 *
 * Base class for file-based XML configuration.
 */

#include "internal.h"

#include "AgentConfig.h"
#include "logging/Category.h"
#include "util/PathResolver.h"
#include "util/ReloadableXMLFile.h"

#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

using namespace boost::property_tree;
using namespace shibsp;
using namespace std;

ReloadableXMLFile::ReloadableXMLFile(const std::string& path, Category& log, bool reloadChanges, bool deprecationSupport)
    : m_tree(nullptr), m_log(log), m_source(path), m_filestamp(0)
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

    m_tree = load();
}

ReloadableXMLFile::~ReloadableXMLFile()
{
}

unique_ptr<ptree> ReloadableXMLFile::load()
{
    try {
        unique_ptr<ptree> pt = unique_ptr<ptree>(new ptree());
        xml_parser::read_xml(m_source, *pt, xml_parser::no_comments|xml_parser::trim_whitespace);
        return pt;
    } catch (const bad_alloc& e) {
        m_log.crit("out of memory parsing XML configuration (%s)", m_source.c_str());
    } catch (const xml_parser_error& e) {
        m_log.error("failed to process XML configuration (%s): %s", m_source.c_str(), e.what());
    }
    return nullptr;
}

void ReloadableXMLFile::lock()
{
    if (m_lock) {
        m_lock->lock();
    }
}

bool ReloadableXMLFile::try_lock()
{
    if (m_lock) {
        return m_lock->try_lock();
    }
}

void ReloadableXMLFile::unlock()
{
    if (m_lock)
        m_lock->unlock();
}

void ReloadableXMLFile::lock_shared()
{
    if (!m_lock) {
        return;
    }

    m_lock->lock_shared();

    // Check if we need to refresh.
#ifdef WIN32
    struct _stat stat_buf;
    if (_stat(m_source.c_str(), &stat_buf) != 0) {
        return;
    }
#else
    struct stat stat_buf;
    if (stat(m_source.c_str(), &stat_buf) != 0) {
        return;
    }
#endif
    if (m_filestamp >= stat_buf.st_mtime) {
        return;
    }

    m_lock->unlock();
    m_log.info("change detected...");

    unique_ptr<ptree> newtree = load();

    if (newtree) {
        m_log.info("swapping in new configuration");
        m_lock->lock();
#ifdef WIN32
        if (_stat(m_source.c_str(), &stat_buf) == 0) {
#else
        if (stat(m_source.c_str(), &stat_buf) == 0) {
#endif
            m_filestamp = stat_buf.st_mtime;
        }
        m_tree.swap(newtree);
        m_lock->unlock();
        m_lock->lock_shared();
    } else {
        m_log.info("new configuration was invalid, retaining original");
        m_lock->lock_shared();
    }
}

bool ReloadableXMLFile::try_lock_shared()
{
    if (m_lock)
        return m_lock->try_lock_shared();
    else
        return true;
}

void ReloadableXMLFile::unlock_shared()
{
    if (m_lock)
        m_lock->unlock_shared();
}

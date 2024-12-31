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
 * util/ReloadableXMLFile.cpp
 *
 * Base class for XML file-based configuration.
 */

#include "internal.h"

#include "AgentConfig.h"
#include "logging/Category.h"
#include "util/Misc.h"
#include "util/PathResolver.h"
#include "util/ReloadableXMLFile.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <boost/property_tree/xml_parser.hpp>

using namespace boost::property_tree;
using namespace shibsp;
using namespace std;

const char ReloadableXMLFile::PATH_PROP_NAME[] = "path";
const char ReloadableXMLFile::RELOAD_CHANGES_PROP_NAME[] = "reloadChanges";

ReloadableXMLFile::ReloadableXMLFile(const string& rootElementName, ptree& pt, Category& log)
    : m_root(pt), m_log(log), m_rootElementName(rootElementName), m_filestamp(0)
#ifdef HAVE_CXX17
        , m_lock(nullptr)
#elif HAVE_CXX14
        , m_lock(nullptr)
#endif
{
    boost::optional<ptree&> xmlattr = pt.get_child_optional("<xmlattr>");
    const ptree& property_root = xmlattr ? xmlattr.get() : pt;

    boost::optional<string> path = property_root.get_optional<string>(PATH_PROP_NAME);
    if (path) {
        m_source = path.get();
        AgentConfig::getConfig().getPathResolver().resolve(m_source, PathResolver::SHIBSP_CFG_FILE);

        string_to_bool_translator tr;
        bool reloadChanges = property_root.get(RELOAD_CHANGES_PROP_NAME, false, tr);
#ifndef HAVE_CXX14
        if (reloadChanges) {
            log.warn("C++ compiler level does not allow for reloadChanges, ignoring");
            reloadChanges = false;
        }
#endif
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

ReloadableXMLFile::~ReloadableXMLFile()
{
}

time_t ReloadableXMLFile::getLastModified() const
{
    return m_filestamp;
}

bool ReloadableXMLFile::isUpdated() const
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

void ReloadableXMLFile::updateModificationTime()
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

void ReloadableXMLFile::updateModificationTime(time_t t)
{
    m_filestamp = t;
}

pair<bool,ptree*> ReloadableXMLFile::load() noexcept
{
    try {
        if (m_source.empty()) {
            m_log.debug("loading inline configuration...");
            // Data comes from the tree we were handed by locating a subtree of the expected name.
            const boost::optional<const ptree&> child = m_root.get_child_optional(m_rootElementName);
            if (!child) {
                throw xml_parser_error("XML missing expected child element: " + m_rootElementName, "inline", 0);
            }
            // The const_cast is safe because the flag is false,
            // preventing the caller from retaining ownership.
            return make_pair(false, const_cast<ptree*>(&m_root));
        }

        unique_ptr<ptree> newtree = unique_ptr<ptree>(new ptree());
        xml_parser::read_xml(m_source, *newtree, xml_parser::no_comments|xml_parser::trim_whitespace);

        // Data comes from the tree we were handed by locating a subtree of the expected name.
        const boost::optional<ptree&> child = newtree->get_child_optional(m_rootElementName);
        if (!child) {
            throw xml_parser_error("XML missing expected child element: " + m_rootElementName, m_source, 0);
        }

        return make_pair(true, newtree.release());
    } catch (const bad_alloc&) {
        m_log.crit("out of memory parsing XML configuration (%s)", m_source.c_str());
    } catch (const xml_parser_error& e) {
        m_log.error("failed to process XML configuration: %s", e.what());
    }

    return make_pair(false, nullptr);
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
    } else {
        return true;
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
    if (!isUpdated()) {
        return;
    }

    m_lock->unlock();
    m_log.info("change detected, attempting reload...");

    // TODO: maybe a second mutex could guard the reload operation so > 1 thread doesn't try it?

    // The result is handled entirely by the subclass so is ignored here.
    // The original root tree is purely a means of communicating the object
    // from the c'tor over to the load method for the inline case, at first load.
    load();

    m_lock->lock_shared();
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

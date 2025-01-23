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


#include "ModuleConfig.h"

#include <shibsp/Agent.h>
#include <shibsp/AgentConfig.h>
#include <shibsp/logging/Category.h>
#include <shibsp/util/BoostPropertySet.h>
#include <shibsp/util/PathResolver.h>

#include <map>
#include <memory>
#include <string>
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/xml_parser.hpp>

using namespace shibsp;
using namespace shibsp::iis;
using namespace boost::property_tree;
using namespace std;

namespace {

    class ModuleConfigImpl : public virtual ModuleConfig, public virtual BoostPropertySet {
    public:
        ModuleConfigImpl(unique_ptr<ptree> pt, bool xml);

        const PropertySet* getSiteConfig(const char* id) const;

        virtual ~ModuleConfigImpl() {}

    private:
        void doSites(ptree& parent);

        Category& m_log;
        unique_ptr<ptree> m_root;
        map<string,unique_ptr<PropertySet>> m_sites;
    };

};

const char ModuleConfig::USE_VARIABLES_PROP_NAME[] = "useVariables";
const char ModuleConfig::USE_HEADERS_PROP_NAME[] = "useHeaders";
const char ModuleConfig::AUTHENTICATED_ROLE_PROP_NAME[] = "authenticatedRole";
const char ModuleConfig::ROLE_ATTRIBUTES_PROP_NAME[] = "roleAttributes";
const char ModuleConfig::NORMALIZE_REQUEST_PROP_NAME[] = "normalizeRequest";
const char ModuleConfig::SAFE_HEADER_NAMES_PROP_NAME[] = "safeHeaderNames";
const char ModuleConfig::HANDLER_PREFIX_PROP_NAME[] = "handlerPrefix";

bool ModuleConfig::USE_VARIABLES_PROP_DEFAULT = true;
bool ModuleConfig::USE_HEADERS_PROP_DEFAULT = false;
const char ModuleConfig::AUTHENTICATED_ROLE_PROP_DEFAULT[] = "ShibbolethAuthN";
bool ModuleConfig::NORMALIZE_REQUEST_PROP_DEFAULT = true;
const char ModuleConfig::HANDLER_PREFIX_PROP_DEFAULT[] = "/Shibboleth.sso";

const char ModuleConfig::SITE_NAME_PROP_NAME[] = "name";
const char ModuleConfig::SITE_SCHEME_PROP_NAME[] = "scheme";
const char ModuleConfig::SITE_PORT_PROP_NAME[] = "port";
const char ModuleConfig::SITE_SSLPORT_PROP_NAME[] = "sslport";
const char ModuleConfig::SITE_ALIASES_PROP_NAME[] = "aliases";

ModuleConfig::ModuleConfig() {}

ModuleConfig::~ModuleConfig() {}

ModuleConfigImpl::ModuleConfigImpl(unique_ptr<ptree> pt, bool xml)
    : m_log(Category::getInstance(SHIBSP_LOGCAT ".IIS")), m_root(std::move(pt))
{
    if (xml) {
        // Size was checked by caller as 1, so a single child exists.
        ptree& child = m_root->front().second;

        // Migrate Roles element's attributes to this child for compatibility with INI format.
        const boost::optional<ptree&> roles = child.get_child_optional("Roles");
        if (roles) {
            const boost::optional<ptree&> xmlattr = roles->get_child_optional(XMLATTR_NODE_NAME);
            if (xmlattr) {
                boost::optional<string> prop = xmlattr->get_optional<string>("authNRole");
                if (prop) {
                    string propname(XMLATTR_NODE_NAME);
                    propname = propname + '.' + AUTHENTICATED_ROLE_PROP_NAME;
                    child.add(propname, *prop);
                }
                prop = xmlattr->get_optional<string>(ROLE_ATTRIBUTES_PROP_NAME);
                if (prop) {
                    string propname(XMLATTR_NODE_NAME);
                    propname = propname + '.' + ROLE_ATTRIBUTES_PROP_NAME;
                    child.add(propname, *prop);
                }
            }
        }

        // Load the final property set.
        load(child);

        // Sites are in children of the root element, which is the first child.
        doSites(child);
    } else {
        const boost::optional<ptree&> global = m_root->get_child_optional("global");
        if (global) {
            load(global.get());
        }
        else {
            m_log.info("IIS configuration missing [global] section, using defaults");
        }
        // Sites are in children of the root of the tree.
        doSites(*m_root);
    }
}

void ModuleConfigImpl::doSites(ptree& parent)
{
    for (auto& child : parent) {
        if (child.first == "Site") {
            unique_ptr<BoostPropertySet> propset(new BoostPropertySet());
            propset->load(child.second);
            propset->setParent(this);

            const char* id = propset->getString("id");

            if (!id || !propset->hasProperty("name")) {
                m_log.warn("ignoring Site element without 'id' or 'name' attributes");
                continue;
            }

            // Check for Alias children to remap into a delimited string.
            string aliases;
            for (const auto& alias : child.second) {
                if (alias.first == "Alias" && !alias.second.get_value<string>().empty()) {
                    if (!aliases.empty()) {
                        aliases += ' ';
                    }
                    aliases += alias.second.get_value<string>();
                }
            }
            if (!aliases.empty()) {
                string propname(XMLATTR_NODE_NAME);
                propname = propname + '.' + SITE_ALIASES_PROP_NAME;
                child.second.add(propname, aliases);
            }

            m_sites[id] = std::move(propset);
            m_log.info("installed Site mapping for (%s)", id);
        }
        else if (child.first == XMLATTR_NODE_NAME || child.first == "Roles") {
            continue;
        }
        else {
            // This is assumed to be an INI format site section. If not, so be it.

            if (!child.second.get_child_optional(SITE_NAME_PROP_NAME).has_value()) {
                m_log.warn("ignoring Site section (%s) with no '%s' property", child.first.c_str(), SITE_NAME_PROP_NAME);
                continue;
            }

            unique_ptr<BoostPropertySet> propset(new BoostPropertySet());
            propset->load(child.second);
            m_sites[child.first] = std::move(propset);
            m_log.info("installed Site mapping for (%s)", child.first.c_str());
        }
    }
}

const PropertySet* ModuleConfigImpl::getSiteConfig(const char* id) const
{
    if (id) {
        auto site = m_sites.find(id);
        if (site != m_sites.end()) {
            return site->second.get();
        }
    }
    return nullptr;
}

unique_ptr<ModuleConfig> ModuleConfig::newModuleConfig(const char* path)
{
    string resolved_path(path ? path : "");
    if (!path) {
        static const char IIS_CONFIG_PATH_PROP_PATH[] = "IISConfigPath";
        resolved_path = AgentConfig::getConfig().getAgent().getString(IIS_CONFIG_PATH_PROP_PATH, "iis-config.ini");
    }
    AgentConfig::getConfig().getPathResolver().resolve(resolved_path, PathResolver::SHIBSP_CFG_FILE);

    unique_ptr<ptree> config_root(new ptree());

    bool xml = false;
    if (boost::ends_with(resolved_path, ".xml")) {
        xml_parser::read_xml(resolved_path, *config_root, xml_parser::trim_whitespace | xml_parser::no_comments);
        xml = true;
        if (config_root->size() != 1) {
            throw xml_parser_error("XML-based IIS module config did not contain a root element?", path, 1);
        }
    }
    else {
        ini_parser::read_ini(resolved_path, *config_root);
    }

    return unique_ptr<ModuleConfig>(new ModuleConfigImpl(std::move(config_root), xml));
}

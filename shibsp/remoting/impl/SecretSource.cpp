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
 * remoting/impl/SecretSource.cpp
 *
 * Implementations for obtaining secrets for RemotingService authentication.
 */

#include "internal.h"
#include "exceptions.h"

#include "AgentConfig.h"
#include "remoting/SecretSource.h"

#include <fstream>
#include <boost/property_tree/ptree.hpp>

using namespace shibsp;
using namespace boost::property_tree;
using namespace std;

namespace {

    class FileSecretSource : public virtual SecretSource {
    public:
        FileSecretSource(const ptree& pt);
        virtual ~FileSecretSource() {}

        string getSecret(const char* key=nullptr) const;

    private:
        string m_pathname;
    };

    class EnvSecretSource : public virtual SecretSource {
    public:
        EnvSecretSource(const ptree& pt);
        virtual ~EnvSecretSource() {}

        string getSecret(const char* key=nullptr) const;

    private:
        string m_envname;
    };

    SecretSource* SHIBSP_DLLLOCAL FileSecretSourceFactory(ptree& pt, bool deprecationSUpport) {
        return new FileSecretSource(pt);
    }

    SecretSource* SHIBSP_DLLLOCAL EnvSecretSourceFactory(ptree& pt, bool deprecationSUpport) {
        return new EnvSecretSource(pt);
    }
};

void SHIBSP_API shibsp::registerSecretSources()
{
    AgentConfig::getConfig().SecretSourceManager.registerFactory(FILE_SECRET_SOURCE, FileSecretSourceFactory);
    AgentConfig::getConfig().SecretSourceManager.registerFactory(ENV_SECRET_SOURCE, EnvSecretSourceFactory);
}

SecretSource::SecretSource() {}

SecretSource::~SecretSource() {}

FileSecretSource::FileSecretSource(const ptree& pt)
{
    static const char SECRET_FILE_PROP_NAME[] = "secretFile";
    m_pathname = pt.get(SECRET_FILE_PROP_NAME, "");
    if (m_pathname.empty()) {
        throw ConfigurationException("Configuration is missing required secret filename setting.");
    }

    // Test for early detection.
    getSecret(nullptr);
}

string FileSecretSource::getSecret(const char*) const
{
    ifstream src(m_pathname, ios::in);
    if (!src) {
        throw IOException("Error accessing secret in " + m_pathname);
    }

    string val;
    src >> val;
    return val;
}

EnvSecretSource::EnvSecretSource(const ptree& pt)
{
    static const char SECRET_ENV_PROP_NAME[] = "secretEnv";
    m_envname = pt.get(SECRET_ENV_PROP_NAME, "");
    if (m_envname.empty()) {
        throw ConfigurationException("Configuration is missing required secret environment variable setting.");
    }

    // Test for early detection.
    getSecret(nullptr);
}

string EnvSecretSource::getSecret(const char*) const
{
    const char* val = getenv(m_envname.c_str());
    if (!val || !*val) {
        throw IOException("No value found in " + m_envname + " environment variable.");
    }

    return val;
}

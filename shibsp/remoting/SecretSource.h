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
 * @file shibsp/remoting/SecretSource.h
 *
 * Interface to obtain secrets for RemotingService authentication.
 */

#ifndef __shibsp_secretsource_h__
#define __shibsp_secretsource_h__

#include <shibsp/base.h>

#include <string>

namespace shibsp {

    /**
     * Interface to a source of secrets.
     */
    class SHIBSP_API SecretSource
    {
        MAKE_NONCOPYABLE(SecretSource);
    protected:
        SecretSource();
    public:
        virtual ~SecretSource();

        /**
         * Obtains a secret, which may contain binary data but may not contain nulls.
         * 
         * <p>Not all implementations support keyed/multiple secrets. Failure
         * to obtain the specified secret will result in an exception.</p>
         * 
         * @param key an identifier defining which secret to access
         * 
         * @return a secret
         */
        virtual std::string getSecret(const char* key) const=0;
    };

    /**
     * Registers RemotingService classes into the runtime.
     */
    void SHIBSP_API registerSecretSources();

    /** RemotingService based on a local file. */
    #define FILE_SECRET_SOURCE "File"

    /** RemotingService based on an environment variable. */
    #define ENV_SECRET_SOURCE "Env"
};

#endif /* __shibsp_secretsource_h__ */

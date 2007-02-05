/*
 *  Copyright 2001-2007 Internet2
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* shib.h - Shibboleth header file

   Scott Cantor
   6/4/02

   $History:$
*/

#ifndef __shib_h__
#define __shib_h__

#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <xmltooling/security/TrustEngine.h>

#include <saml/saml.h>
#undef SAML10_PROTOCOL_ENUM

#ifdef WIN32
# ifndef SHIB_EXPORTS
#  define SHIB_EXPORTS __declspec(dllimport)
# endif
#else
# define SHIB_EXPORTS
#endif

namespace shibboleth
{
    struct SHIB_EXPORTS IAttributeFactory : public virtual saml::IPlugIn
    {
        virtual saml::SAMLAttribute* build(DOMElement* e) const=0;
        virtual ~IAttributeFactory() {}
    };

    // Subclass around the OpenSAML browser profile interface,
    // incoporates additional functionality using Shib-defined APIs.
    class SHIB_EXPORTS ShibBrowserProfile : virtual public saml::SAMLBrowserProfile
    {
    public:
        struct SHIB_EXPORTS ITokenValidator {
            virtual void validateToken(
                saml::SAMLAssertion* token,
                time_t=0,
                const opensaml::saml2md::RoleDescriptor* role=NULL,
                const xmltooling::TrustEngine* trustEngine=NULL
                ) const=0;
            virtual ~ITokenValidator() {}
        };

        ShibBrowserProfile(
            const ITokenValidator* validator,
            opensaml::saml2md::MetadataProvider* metadata=NULL,
            xmltooling::TrustEngine* trust=NULL
            );
        virtual ~ShibBrowserProfile();

        virtual saml::SAMLBrowserProfile::BrowserProfileResponse receive(
            const char* samlResponse,
            const XMLCh* recipient,
            saml::IReplayCache* replayCache,
            int minorVersion=1
            ) const;
        virtual saml::SAMLBrowserProfile::BrowserProfileResponse receive(
            saml::Iterator<const char*> artifacts,
            const XMLCh* recipient,
            saml::SAMLBrowserProfile::ArtifactMapper* artifactMapper,
            saml::IReplayCache* replayCache,
            int minorVersion=1
            ) const;

    private:
        void postprocess(saml::SAMLBrowserProfile::BrowserProfileResponse& bpr, int minorVersion=1) const;

        saml::SAMLBrowserProfile* m_profile;
        opensaml::saml2md::MetadataProvider* m_metadata;
        xmltooling::TrustEngine* m_trust;
        const ITokenValidator* m_validator;
    };

    class SHIB_EXPORTS ShibConfig
    {
    public:
        ShibConfig() {}
        virtual ~ShibConfig() {}

        // global per-process setup and shutdown of Shibboleth runtime
        virtual bool init();
        virtual void term();

        // manages specific attribute name to factory mappings
        void regAttributeMapping(const XMLCh* name, const IAttributeFactory* factory);
        void unregAttributeMapping(const XMLCh* name);
        void clearAttributeMappings();

        // enables runtime and clients to access configuration
        static ShibConfig& getConfig();
    };
}

#endif

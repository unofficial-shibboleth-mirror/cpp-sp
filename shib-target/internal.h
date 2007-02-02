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

/* internal.h - internally visible declarations

   Scott Cantor
   6/29/03

   $History:$
*/

#ifndef __shibtarget_internal_h__
#define __shibtarget_internal_h__

#ifdef WIN32
# define _CRT_SECURE_NO_DEPRECATE 1
# define _CRT_NONSTDC_NO_DEPRECATE 1
#endif

#ifdef WIN32
# define SHIBTARGET_EXPORTS __declspec(dllexport)
#endif

// eventually we might be able to support autoconf via cygwin...
#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#include <shibsp/util/SPConstants.h>

#include "shib-target.h"
#include "hresult.h"

#include <log4cpp/Category.hh>
#include <log4cpp/FixedContextCategory.hh>
#include <shibsp/exceptions.h>
#include <xmltooling/PluginManager.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/Threads.h>


#define SHIBT_L(s) shibtarget::XML::Literals::s
#define SHIBT_L_QNAME(p,s) shibtarget::XML::Literals::p##_##s
#define SHIBT_LOGCAT "shibtarget"
#define SHIBTRAN_LOGCAT "Shibboleth-TRANSACTION"

namespace shibtarget {
    // ST-aware class that maps SAML artifacts to appropriate binding information
    class STArtifactMapper : public virtual saml::SAMLBrowserProfile::ArtifactMapper
    {
    public:
        STArtifactMapper(const IApplication* application) : m_app(application) {}
        virtual ~STArtifactMapper() {}
        saml::SAMLResponse* resolve(saml::SAMLRequest* request);
    
    private:
        const IApplication* m_app;
    };

    class STConfig : public ShibTargetConfig
    {
    public:
        STConfig() : m_tranLog(NULL), m_tranLogLock(NULL) {}
        ~STConfig() {}
        
        bool init(const char* schemadir);
        bool load(const char* config);
        void shutdown();

        log4cpp::Category& getTransactionLog() { m_tranLogLock->lock(); return *m_tranLog; }
        void releaseTransactionLog() { m_tranLogLock->unlock();}
    private:
        log4cpp::FixedContextCategory* m_tranLog;
        xmltooling::Mutex* m_tranLogLock;
    };
    
    // TODO: move this over to shibsp lib.
    xmltooling::PluginManager<shibsp::ServiceProvider,const DOMElement*>::Factory XMLServiceProviderFactory;
}

#endif

/*
 * The Shibboleth License, Version 1.
 * Copyright (c) 2002
 * University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution, if any, must include
 * the following acknowledgment: "This product includes software developed by
 * the University Corporation for Advanced Internet Development
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement
 * may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear.
 *
 * Neither the name of Shibboleth nor the names of its contributors, nor
 * Internet2, nor the University Corporation for Advanced Internet Development,
 * Inc., nor UCAID may be used to endorse or promote products derived from this
 * software without specific prior written permission. For written permission,
 * please contact shibboleth@shibboleth.org
 *
 * Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor
 * may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * shib-config.cpp -- ShibTarget initialization and finalization routines
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include "internal.h"

#include <shib/shib-threads.h>

#include <log4cpp/PropertyConfigurator.hh>
#include <log4cpp/Category.hh>

#ifndef SHIBTARGET_INIFILE
#define SHIBTARGET_INIFILE "/opt/shibboleth/etc/shibboleth/shibboleth.ini"
#endif

class STConfig : public ShibTargetConfig
{
public:
  STConfig(const char* app_name, const char* inifile);
  ~STConfig();
  void shutdown();
  void init();
  ShibINI& getINI() { return *ini; }

  Iterator<const XMLCh*> getPolicies() { return Iterator<const XMLCh*>(policies); }

  void ref();
private:
  SAMLConfig& samlConf;
  ShibConfig& shibConf;
  ShibINI* ini;
  string m_app_name;
  int refcount;
  vector<const XMLCh*> policies;
  string m_SocketName;
#ifdef WANT_TCP_SHAR
  vector<string> m_SocketACL;
#endif
  friend ShibSockName shib_target_sockname();
  friend ShibSockName shib_target_sockacl(unsigned int);
};

namespace {
  STConfig * g_Config = NULL;
  Mutex * g_lock = NULL;
}

CCache* shibtarget::g_shibTargetCCache = NULL;

/****************************************************************************/
// External Interface


void ShibTargetConfig::preinit()
{
  if (g_lock) return;
  g_lock = Mutex::create();
}

ShibTargetConfig& ShibTargetConfig::init(const char* app_name, const char* inifile)
{
  if (!g_lock)
    throw runtime_error ("ShibTargetConfig not pre-initialized");

  if (!app_name)
    throw runtime_error ("No Application name");
  Lock lock(g_lock);

  if (g_Config) {
    g_Config->ref();
    return *g_Config;
  }

  g_Config = new STConfig(app_name, inifile);
  g_Config->init();
  return *g_Config;
}

ShibTargetConfig& ShibTargetConfig::getConfig()
{
    if (!g_Config)
        throw SAMLException("ShibTargetConfig::getConfig() called with NULL configuration");
    return *g_Config;
}

/****************************************************************************/
// STConfig

STConfig::STConfig(const char* app_name, const char* inifile)
  :  samlConf(SAMLConfig::getConfig()), shibConf(ShibConfig::getConfig()),
     m_app_name(app_name)
{
  try {
    ini = new ShibINI((inifile ? inifile : SHIBTARGET_INIFILE));
  } catch (...) {
    cerr << "Unable to load the INI file: " << 
      (inifile ? inifile : SHIBTARGET_INIFILE) << endl;
    throw;
  }
}

void STConfig::init()
{
  string app = m_app_name;
  string tag;

  // Initialize Log4cpp
  if (ini->get_tag (app, SHIBTARGET_TAG_LOGGER, true, &tag)) {
    cerr << "Loading new logging configuration from " << tag << "\n";
    try {
      PropertyConfigurator::configure(tag);
      cerr << "New logging configuration loaded, check log destination for process status..." << "\n";
    } catch (ConfigureFailure& e) {
      cerr << "Error reading configuration: " << e.what() << "\n";
    }
  } else {
    Category& category = Category::getRoot();
    category.setPriority(log4cpp::Priority::DEBUG);
    cerr << "No logger configuration found\n";
  }

  Category& log = Category::getInstance("shibtarget.STConfig");

  saml::NDC ndc("STConfig::init");

  // Init SAML Configuration
  if (ini->get_tag (app, SHIBTARGET_TAG_SAMLCOMPAT, true, &tag))
    samlConf.compatibility_mode = ShibINI::boolean(tag);
  if (ini->get_tag (app, SHIBTARGET_TAG_SCHEMAS, true, &tag))
    samlConf.schema_dir = tag;

  // Init SAML Binding Configuration
  if (ini->get_tag (app, SHIBTARGET_TAG_AATIMEOUT, true, &tag))
    samlConf.binding_defaults.timeout = atoi(tag.c_str());
  if (ini->get_tag (app, SHIBTARGET_TAG_AACONNECTTO, true, &tag))
    samlConf.binding_defaults.conn_timeout = atoi(tag.c_str());
  if (ini->get_tag (app, SHIBTARGET_TAG_CERTFILE, true, &tag))
    samlConf.binding_defaults.ssl_certfile = tag;
  if (ini->get_tag (app, SHIBTARGET_TAG_KEYFILE, true, &tag))
    samlConf.binding_defaults.ssl_keyfile = tag;
  if (ini->get_tag (app, SHIBTARGET_TAG_KEYPASS, true, &tag))
    samlConf.binding_defaults.ssl_keypass = tag;
  if (ini->get_tag (app, SHIBTARGET_TAG_CALIST, true, &tag))
    samlConf.binding_defaults.ssl_calist = tag;

  try {
    if (!samlConf.init()) {
      log.fatal ("Failed to initialize SAML Library");
      throw runtime_error ("Failed to initialize SAML Library");
    } else
      log.debug ("SAML Initialized");
  } catch (...) {
    log.crit ("Died initializing SAML Library");
    throw;    
  }

  // Init Shib
  try { 
    if (!shibConf.init()) {
      log.fatal ("Failed to initialize Shib library");
      throw runtime_error ("Failed to initialize Shib Library");
    } else
      log.debug ("Shib Initialized");
  } catch (...) {
    log.crit ("Failed initializing Shib library.");
    throw;
  }

  // Load any SAML extensions
  string ext = "extensions:saml";
  if (ini->exists(ext)) {
    saml::NDC ndc("load_extensions");
    ShibINI::Iterator* iter = ini->tag_iterator(ext);

    for (const string* str = iter->begin(); str; str = iter->next()) {
      string file = ini->get(ext, *str);
      try
      {
        samlConf.saml_register_extension(file.c_str(),ini);
        log.debug("%s: loading %s", str->c_str(), file.c_str());
      }
      catch (SAMLException& e)
      {
        log.crit("%s: %s", str->c_str(), e.what());
      }
    }
    delete iter;
  }

  // Load the specified metadata.
  if (ini->get_tag(app, SHIBTARGET_TAG_METADATA, true, &tag) && ini->exists(tag))
  {
    ShibINI::Iterator* iter=ini->tag_iterator(tag);
    for (const string* prov=iter->begin(); prov; prov=iter->next())
    {
        const string source=ini->get(tag,*prov);
        log.info("registering metadata provider: type=%s, source=%s",prov->c_str(),source.c_str());
        if (!shibConf.addMetadata(prov->c_str(),source.c_str()))
        {
            log.crit("error adding metadata provider: type=%s, source=%s",prov->c_str(),source.c_str());
            if (!strcmp(app.c_str(), SHIBTARGET_SHAR))
                throw runtime_error("error adding metadata provider");
        }
    }
    delete iter;
  }
  
  // Backward-compatibility-hack to pull in aap-uri from [shire] and load
  // as attribute metadata. We load this for anything, not just the SHIRE.
  if (ini->get_tag(SHIBTARGET_SHIRE, "aap-uri", false, &tag))
  {
    log.warn("using DEPRECATED aap-uri setting for backward compatibility, please read the latest target deploy guide");
    log.info("registering metadata provider: type=edu.internet2.middleware.shibboleth.target.AAP.XML, source=%s",tag.c_str());
    if (!shibConf.addMetadata("edu.internet2.middleware.shibboleth.target.AAP.XML",tag.c_str()))
    {
        log.crit("error adding metadata provider: type=edu.internet2.middleware.shibboleth.target.AAP.XML, source=%s",tag.c_str());
        if (!strcmp(app.c_str(), SHIBTARGET_SHAR))
            throw runtime_error("error adding metadata provider");
    }
  }
  
  // Load SAML policies.
  if (ini->exists(SHIBTARGET_POLICIES)) {
    log.info("loading SAML policies");
    ShibINI::Iterator* iter = ini->tag_iterator(SHIBTARGET_POLICIES);

    for (const string* str = iter->begin(); str; str = iter->next()) {
        policies.push_back(XMLString::transcode(ini->get(SHIBTARGET_POLICIES, *str).c_str()));
    }
    delete iter;
  }
  
  // Initialize the SHAR Cache
  if (!strcmp (app.c_str(), SHIBTARGET_SHAR)) {
    const char * cache_type = NULL;
    if (ini->get_tag (app, SHIBTARGET_TAG_CACHETYPE, true, &tag))
      cache_type = tag.c_str();

    g_shibTargetCCache = CCache::getInstance(cache_type);
  }

  // Process socket settings.
  m_SocketName=ini->get(SHIBTARGET_GENERAL, "sharsocket");
  if (m_SocketName.empty())
    m_SocketName=SHIB_SHAR_SOCKET;

#ifdef WANT_TCP_SHAR
  string sockacl=ini->get(SHIBTARGET_SHAR, "sharacl");
  if (sockacl.length()>0)
  {
    int j = 0;
    for (int i = 0;  i < sockacl.length();  i++)
    {
        if (sockacl.at(i)==' ')
        {
            string addr=sockacl.substr(j, i-j);
            j = i+1;
            m_SocketACL.push_back(addr);
        }
    }
    string addr=sockacl.substr(j, sockacl.length()-j);
    m_SocketACL.push_back(addr);
  }
  else
    m_SocketACL.push_back("127.0.0.1");
#endif

  ref();
  log.debug("finished");
}

STConfig::~STConfig()
{
  for (vector<const XMLCh*>::iterator i=policies.begin(); i!=policies.end(); i++)
    delete const_cast<XMLCh*>(*i);
  
  delete g_shibTargetCCache;
  delete ini;

  shibConf.term();
  samlConf.term();
}

void STConfig::ref()
{
  refcount++;
}

void STConfig::shutdown()
{
  refcount--;
  if (!refcount) {
    delete g_Config;
    g_Config = NULL;
  }
}

extern "C" ShibSockName shib_target_sockname(void)
{
    return (g_Config ? g_Config->m_SocketName.c_str() : (ShibSockName)0);
}

extern "C" ShibSockName shib_target_sockacl(unsigned int index)
{
#ifdef WANT_TCP_SHAR
    if (g_Config && index<g_Config->m_SocketACL.size())
        return g_Config->m_SocketACL[index].c_str();
#endif
    return (ShibSockName)0;
}

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

using namespace std;
using namespace log4cpp;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

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
     m_app_name(app_name), m_applicationMapper(NULL), refcount(0)
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

    DOMImplementation* impl=DOMImplementationRegistry::getDOMImplementation(NULL);
    DOMDocument* dummydoc=impl->createDocument();
    DOMElement* dummy = dummydoc->createElementNS(NULL,XML::Literals::ApplicationMap);

    // Load the specified metadata, trust, creds, and aap sources.
    static const XMLCh url[] = { chLatin_u, chLatin_r, chLatin_l, chNull };
    const string* prov;
    ShibINI::Iterator* iter=ini->tag_iterator(SHIBTARGET_TAG_METADATA);
    for (prov=iter->begin(); prov; prov=iter->next()) {
        string source=ini->get(SHIBTARGET_TAG_METADATA,*prov);
        log.info("building metadata provider: type=%s, source=%s",prov->c_str(),source.c_str());
        try {
            auto_ptr_XMLCh src(source.c_str());
            dummy->setAttributeNS(NULL,url,src.get());
            metadatas.push_back(shibConf.newMetadata(prov->c_str(),dummy));
        }
        catch (exception& e) {
            log.crit("error building metadata provider: type=%s, source=%s (%s)",prov->c_str(),source.c_str(),e.what());
            if (app == SHIBTARGET_SHAR)
                throw;
        }
    }
    delete iter;

    iter=ini->tag_iterator(SHIBTARGET_TAG_AAP);
    for (prov=iter->begin(); prov; prov=iter->next()) {
        string source=ini->get(SHIBTARGET_TAG_AAP,*prov);
        log.info("building AAP provider: type=%s, source=%s",prov->c_str(),source.c_str());
        try {
            auto_ptr_XMLCh src(source.c_str());
            dummy->setAttributeNS(NULL,url,src.get());
            aaps.push_back(shibConf.newAAP(prov->c_str(),dummy));
        }
        catch (exception& e) {
            log.crit("error building AAP provider: type=%s, source=%s (%s)",prov->c_str(),source.c_str(),e.what());
            if (app == SHIBTARGET_SHAR)
                throw;
        }
    }
    delete iter;
    
    if (app == SHIBTARGET_SHAR) {
        iter=ini->tag_iterator(SHIBTARGET_TAG_TRUST);
        for (prov=iter->begin(); prov; prov=iter->next()) {
            string source=ini->get(SHIBTARGET_TAG_TRUST,*prov);
            log.info("building trust provider: type=%s, source=%s",prov->c_str(),source.c_str());
            try {
                auto_ptr_XMLCh src(source.c_str());
                dummy->setAttributeNS(NULL,url,src.get());
                trusts.push_back(shibConf.newTrust(prov->c_str(),dummy));
            }
            catch (exception& e) {
                log.crit("error building trust provider: type=%s, source=%s (%s)",prov->c_str(),source.c_str(),e.what());
                throw;
            }
        }
        delete iter;
    
        iter=ini->tag_iterator(SHIBTARGET_TAG_CREDS);
        for (prov=iter->begin(); prov; prov=iter->next()) {
            string source=ini->get(SHIBTARGET_TAG_CREDS,*prov);
            log.info("building creds provider: type=%s, source=%s",prov->c_str(),source.c_str());
            try {
                auto_ptr_XMLCh src(source.c_str());
                dummy->setAttributeNS(NULL,url,src.get());
                creds.push_back(shibConf.newCredentials(prov->c_str(),dummy));
            }
            catch (exception& e) {
                log.crit("error building creds provider: type=%s, source=%s (%s)",prov->c_str(),source.c_str(),e.what());
                throw;
            }
        }
        delete iter;

        iter=ini->tag_iterator(SHIBTARGET_TAG_REVOCATION);
        for (prov=iter->begin(); prov; prov=iter->next()) {
            string source=ini->get(SHIBTARGET_TAG_REVOCATION,*prov);
            log.info("building revocation provider: type=%s, source=%s",prov->c_str(),source.c_str());
            try {
                auto_ptr_XMLCh src(source.c_str());
                dummy->setAttributeNS(NULL,url,src.get());
                revocations.push_back(shibConf.newRevocation(prov->c_str(),dummy));
            }
            catch (exception& e) {
                log.crit("error building revocation provider: type=%s, source=%s (%s)",prov->c_str(),source.c_str(),e.what());
                throw;
            }
        }
        delete iter;
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
  
  if (app == SHIBTARGET_SHIRE && ini->get_tag(app, SHIBTARGET_TAG_APPMAPPER, false, &tag)) {
    saml::XML::registerSchema(shibtarget::XML::APPMAP_NS,shibtarget::XML::APPMAP_SCHEMA_ID);
    try {
        auto_ptr_XMLCh src(tag.c_str());
        dummy->setAttributeNS(NULL,url,src.get());
        m_applicationMapper=new XMLApplicationMapper(dummy);
        dynamic_cast<XMLApplicationMapper*>(m_applicationMapper)->getImplementation();
    }
    catch (exception& e) {
        log.crit("caught exception while loading URL->Application mapping file (%s)", e.what());
    }
    catch (...) {
        log.crit("caught unknown exception while loading URL->Application mapping file");
    }
  }
  
    dummydoc->release();

  // Initialize the SHAR Cache
  if (app == SHIBTARGET_SHAR) {
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
  delete m_applicationMapper;

  for (vector<const XMLCh*>::iterator i=policies.begin(); i!=policies.end(); i++)
    delete const_cast<XMLCh*>(*i);

  for (vector<IMetadata*>::iterator j=metadatas.begin(); j!=metadatas.end(); j++)
    delete (*j);

  for (vector<ITrust*>::iterator k=trusts.begin(); k!=trusts.end(); k++)
    delete (*k);
    
  for (vector<ICredentials*>::iterator l=creds.begin(); l!=creds.end(); l++)
    delete (*l);

  for (vector<IAAP*>::iterator m=aaps.begin(); m!=aaps.end(); m++)
    delete (*m);

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

extern "C" const char* shib_target_sockname(void)
{
    return g_Config ? g_Config->m_SocketName.c_str() : NULL;
}

extern "C" const char* shib_target_sockacl(unsigned int index)
{
#ifdef WANT_TCP_SHAR
    if (g_Config && index<g_Config->m_SocketACL.size())
        return g_Config->m_SocketACL[index].c_str();
#endif
    return NULL;
}

ApplicationMapper::ApplicationMapper() : m_mapper(ShibTargetConfig::getConfig().getApplicationMapper())
{
    if (!m_mapper)
        throw runtime_error("application mapper not initialized, check log for errors");
    m_mapper->lock();
}

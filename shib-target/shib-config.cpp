/*
 * shib-config.cpp -- ShibTarget initialization and finalization routines
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include "shib-target.h"
#include "ccache-utils.h"
#include <shib/shib-threads.h>

#include <log4cpp/PropertyConfigurator.hh>
#include <log4cpp/Category.hh>

using namespace saml;
using namespace shibboleth;
using namespace shibtarget;
using namespace std;

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

ShibTargetConfig::~ShibTargetConfig()
{
#ifdef WIN32
#else
    if (m_SocketName) free(m_SocketName);
#endif
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

extern "C" SAMLAttribute* ScopedFactory(DOMElement* e)
{
    return new ScopedAttribute(e);
}

extern "C" SAMLAttribute* SimpleFactory(DOMElement* e)
{
    return new SimpleAttribute(e);
}

void STConfig::init()
{
  string app = m_app_name;
  string tag;

  // Initialize Log4cpp
  if (ini->get_tag (app, SHIBTARGET_TAG_LOGGER, true, &tag)) {
    cerr << "Trying to load logger configuration: " << tag << "\n";
    try {
      log4cpp::PropertyConfigurator::configure(tag);
    } catch (log4cpp::ConfigureFailure& e) {
      cerr << "Error reading configuration: " << e.what() << "\n";
    }
  } else {
    log4cpp::Category& category = log4cpp::Category::getRoot();
    category.setPriority(log4cpp::Priority::DEBUG);
    cerr << "No logger configuration found\n";
  }

  log4cpp::Category& log = log4cpp::Category::getInstance("shibtarget.STConfig");

  saml::NDC ndc("STConfig::init");

  // Init SAML
  if (ini->get_tag (app, SHIBTARGET_TAG_SCHEMAS, true, &tag))
    samlConf.schema_dir = tag;
  if (ini->get_tag (app, SHIBTARGET_TAG_CERTFILE, true, &tag))
    samlConf.ssl_certfile = tag;
  if (ini->get_tag (app, SHIBTARGET_TAG_KEYFILE, true, &tag))
    samlConf.ssl_keyfile = tag;
  if (ini->get_tag (app, SHIBTARGET_TAG_KEYPASS, true, &tag))
    samlConf.ssl_keypass = tag;
  if (ini->get_tag (app, SHIBTARGET_TAG_CALIST, true, &tag))
    samlConf.ssl_calist = tag;

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
  if (ini->get_tag(app, SHIBTARGET_TAG_AAP, true, &tag))
      shibConf.aapURL=tag;

  if (! ini->get_tag (app, SHIBTARGET_TAG_SITES, true, &tag)) {
    log.fatal("No Sites File found in configuration");
    throw runtime_error ("No Sites File found in configuration");
  }

  shibConf.mapperURL=tag;
  try {
    if (ini->get_tag (app, SHIBTARGET_TAG_SITESCERT, true, &tag)) {
      shibConf.mapperCert = new X509Certificate (X509Certificate::PEM, tag.c_str());
    }
  } catch (...) {
    log.crit ("Can not read the x509 certificate.");
    throw;
  }
  
  try {
    if (ini->get_tag (app, SHIBTARGET_TAG_SITESREFRESH, true, &tag)) {
      shibConf.mapperRefreshInterval = atoi(tag.c_str());
    }
  } catch (...) {
    log.crit ("Can not read the mapper refresh interval.");
    throw;
  }  

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

  // Register attributes based on built-in classes.
  if (ini->exists("attributes")) {
    log.info("registering attributes");
    ShibINI::Iterator* iter=ini->tag_iterator("attributes");
    for (const string* attrname=iter->begin(); attrname; attrname=iter->next())
    {
        const string factory=ini->get("attributes",*attrname);
        if (factory=="scoped")
        {
            auto_ptr<XMLCh> temp(XMLString::transcode(attrname->c_str()));
            SAMLAttribute::regFactory(temp.get(),shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI,&ScopedFactory);
            log.info("registered scoped attribute (%s)",attrname->c_str());
        }
        else if (factory=="simple")
        {
            auto_ptr<XMLCh> temp(XMLString::transcode(attrname->c_str()));
            SAMLAttribute::regFactory(temp.get(),shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI,&SimpleFactory);
            log.info("registered simple attribute (%s)",attrname->c_str());
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
  
  // Initialize the SHAR Cache
  if (!strcmp (app.c_str(), SHIBTARGET_SHAR)) {
    const char * cache_type = NULL;
    if (ini->get_tag (app, SHIBTARGET_TAG_CACHETYPE, true, &tag))
      cache_type = tag.c_str();

    g_shibTargetCCache = CCache::getInstance(cache_type);
  }

  string sockname=ini->get(SHIBTARGET_GENERAL, "sharsocket");
#ifdef WIN32
  if (sockname.length()>0)
    m_SocketName=atoi(sockname.c_str());
  else
    m_SocketName=SHIB_SHAR_SOCKET;
#else
  if (sockname.length()>0)
    m_SocketName=strdup(sockname.c_str());
  else
    m_SocketName=strdup(SHIB_SHAR_SOCKET);
#endif

  ref();
  log.debug("finished");
}

STConfig::~STConfig()
{
  for (vector<const XMLCh*>::iterator i=policies.begin(); i!=policies.end(); i++)
    delete const_cast<XMLCh*>(*i);
    
  // Unregister attributes based on built-in classes.
  if (ini && ini->exists("attributes")) {
    ShibINI::Iterator* iter=ini->tag_iterator("attributes");
    for (const string* attrname=iter->begin(); attrname; attrname=iter->next())
    {
        const string factory=ini->get("attributes",*attrname);
        if (factory=="scoped")
        {
            auto_ptr<XMLCh> temp(XMLString::transcode(attrname->c_str()));
            SAMLAttribute::unregFactory(temp.get(),shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI);
        }
        else if (factory=="simple")
        {
            auto_ptr<XMLCh> temp(XMLString::transcode(attrname->c_str()));
            SAMLAttribute::unregFactory(temp.get(),shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI);
        }
    }
	delete iter;
  }

  if (ini) delete ini;
  
  if (g_shibTargetCCache)
    delete g_shibTargetCCache;

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

/*
 * shib-config.cpp -- ShibTarget initialization and finalization routines
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include "shib-target.h"

#include <log4cpp/PropertyConfigurator.hh>
#include <log4cpp/Category.hh>

using namespace saml;
using namespace shibboleth;
using namespace shibtarget;
using namespace std;

#ifndef SHIBTARGET_INIFILE
#define SHIBTARGET_INIFILE "/etc/shibboleth.ini"
#endif

class STConfig : public ShibTargetConfig
{
public:
  STConfig(const char* app_name, const char* inifile);
  ~STConfig();
  void shutdown();
  ShibINI& getINI() { return *ini; }

  void ref();
private:
  SAMLConfig& samlConf;
  ShibConfig& shibConf;
  ShibINI* ini;
  int refcount;
};

namespace {
  STConfig * g_Config = NULL;
}

CCache* shibtarget::g_shibTargetCCache = NULL;

/****************************************************************************/
// External Interface


ShibTargetConfig& ShibTargetConfig::init(const char* app_name, const char* inifile)
{
  if (!app_name)
    throw runtime_error ("No Application name");

  if (g_Config) {
    g_Config->ref();
    return *g_Config;
  }

  g_Config = new STConfig(app_name, inifile);
  return *g_Config;
}



/****************************************************************************/
// STConfig

STConfig::STConfig(const char* app_name, const char* inifile)
  :  samlConf(SAMLConfig::getConfig()), shibConf(ShibConfig::getConfig())
{
  ini = new ShibINI((inifile ? inifile : SHIBTARGET_INIFILE));

  string app = app_name;
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

  if (!samlConf.init()) {
    log.error ("Failed to initialize SAML Library");
    throw runtime_error ("Failed to initialize SAML Library");
  } else
    log.debug ("SAML Initialized");

  // Init Shib
  if (! ini->get_tag (app, SHIBTARGET_TAG_SITES, true, &tag)) {
    log.crit("No Sites File found in configuration");
    throw runtime_error ("No Sites File found in configuration");
  }

  string sitesFile = tag;
  X509Certificate* verifyKey = NULL;

  if (ini->get_tag (app, SHIBTARGET_TAG_SITESCERT, true, &tag)) {
    verifyKey = new X509Certificate (X509Certificate::PEM, tag.c_str());
  }

  shibConf.origin_mapper = new XMLOriginSiteMapper(sitesFile.c_str(),
						   samlConf.ssl_calist.c_str(),
						   verifyKey);

  if (verifyKey)
    delete verifyKey;
  
  if (!shibConf.init()) {
    log.error ("Failed to initialize Shib library");
    throw runtime_error ("Failed to initialize Shib Library");
  } else
    log.debug ("Shib Initialized");

  // Initialize the SHAR Cache
  if (!strcmp (app_name, SHIBTARGET_SHAR))
    g_shibTargetCCache = CCache::getInstance();  

  // Load any extensions
  string ext = "extensions";
  if (ini->exists(ext)) {
    saml::NDC ndc("load extensions");
    ShibINI::Iterator* iter = ini->tag_iterator(ext);

    for (const string* str = iter->begin(); str; str = iter->next()) {
      string file = ini->get(ext, *str);
      try
      {
	samlConf.saml_register_extension(file.c_str());
	log.debug("%s: loading %s", str->c_str(), file.c_str());
      }
      catch (SAMLException& e)
      {
	log.error("%s: %s", str->c_str(), e.what());
      }
    }
    delete iter;
  }

  ref();
  log.debug("finished");
}

STConfig::~STConfig()
{
  if (ini) delete ini;
  
  if (g_shibTargetCCache)
    delete g_shibTargetCCache;

  delete shibConf.origin_mapper;
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

/*
 * shib-target.cpp -- General target initialization and finalization routines
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

CCache* shibtarget::g_shibTargetCCache = NULL;

/* shib-target.cpp */

#ifndef SHIBTARGET_INIFILE
#define SHIBTARGET_INIFILE "/etc/shibboleth.ini"
#endif

static bool get_tag (ShibINI& ini, string& header, string& tag, bool try_general,
		     string* result)
{
  if (!result) return false;

  if (ini.exists (header, tag)) {
    *result = ini.get(header, tag);
    return true;
  }
  if (try_general && ini.exists (SHIBTARGET_GENERAL, tag)) {
    *result = ini.get(SHIBTARGET_GENERAL, tag);
    return true;
  }
  return false;
}

static bool get_tag (ShibINI& ini, string& header, const char* tag,
		     bool try_general, string* result)
{
  string tag_s = tag;
  return get_tag (ini, header, tag_s, try_general, result);
}

class DummyMapper : public IOriginSiteMapper
{
public:
    DummyMapper();
    ~DummyMapper();
    virtual Iterator<xstring> getHandleServiceNames(const XMLCh* originSite) { return Iterator<xstring>(m_hsnames); }
    virtual Key* getHandleServiceKey(const XMLCh* handleService) { return NULL; }
    virtual Iterator<xstring> getSecurityDomains(const XMLCh* originSite);
    virtual Iterator<X509Certificate*> getTrustedRoots() { return Iterator<X509Certificate*>(); }

private:
    typedef map<xstring,vector<xstring>*> domains_t;
    domains_t m_domains;
    vector<xstring> m_hsnames;
};

DummyMapper::DummyMapper()
{
    auto_ptr<XMLCh> buf(XMLString::transcode("shibprod0.internet2.edu"));
    m_hsnames.push_back(buf.get());
}

Iterator<xstring> DummyMapper::getSecurityDomains(const XMLCh* originSite)
{
    domains_t::iterator i=m_domains.find(originSite);
    if (i==m_domains.end())
    {
        vector<xstring>* pv=new vector<xstring>();
        pv->push_back(originSite);
        pair<domains_t::iterator,bool> p=m_domains.insert(domains_t::value_type(originSite,pv));
	i=p.first;
    }
    return Iterator<xstring>(*(i->second));
}

DummyMapper::~DummyMapper()
{
    for (domains_t::iterator i=m_domains.begin(); i!=m_domains.end(); i++)
        delete i->second;
}

/* initialize and finalize the target library: return 0 on success, 1 on failure */
extern "C" int shib_target_initialize (const char* app_name, const char* inifile)
{
  if (!app_name) {
    cerr << "APPLICATION ERROR: No application supplied to shib_target_init\n";
    return 1;
  }

  // Open the inifile
  ShibINI ini((inifile ? inifile : SHIBTARGET_INIFILE));

  string app = app_name;
  string tag;

  // Initialize Log4cpp
  if (get_tag (ini, app, SHIBTARGET_TAG_LOGGER, true, &tag)) {
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

  log4cpp::Category& log = log4cpp::Category::getInstance("shibtarget.initialize");

  // Initialize SAML and Shib libraries
  SAMLConfig& samlConf = SAMLConfig::getConfig();
  ShibConfig& shibConf = ShibConfig::getConfig();

  // Init SAML
  if (get_tag (ini, app, SHIBTARGET_TAG_SCHEMAS, true, &tag))
    samlConf.schema_dir = tag;
  if (get_tag (ini, app, SHIBTARGET_TAG_CERTFILE, true, &tag))
    samlConf.ssl_certfile = tag;
  if (get_tag (ini, app, SHIBTARGET_TAG_KEYFILE, true, &tag))
    samlConf.ssl_keyfile = tag;
  if (get_tag (ini, app, SHIBTARGET_TAG_KEYPASS, true, &tag))
    samlConf.ssl_keypass = tag;
  if (get_tag (ini, app, SHIBTARGET_TAG_CALIST, true, &tag))
    samlConf.ssl_calist = tag;

  if (!samlConf.init()) {
    log.error ("Failed to initialize SAML Library");
    return 1;
  } else
    log.debug ("SAML Initialized");

  // Init Shib
  shibConf.origin_mapper = new DummyMapper();
  
  if (!shibConf.init()) {
    log.error ("Failed to initialize SHIB library");
    return 1;
  } else
    log.debug ("Shib Initialized");

  // Initialize the SHAR Cache
  if (!strcmp (app_name, SHIBTARGET_SHAR))
    g_shibTargetCCache = CCache::getInstance();  

  // Load any extensions
  string ext = "extensions";
  if (ini.exists(ext)) {
    saml::NDC ndc("load extensions");
    ShibINI::Iterator* iter = ini.tag_iterator(ext);

    for (const string* str = iter->begin(); str; str = iter->next()) {
      string file = ini.get(ext, *str);
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

  log.debug("shib_target_initialize() finished");
  return 0;
}

extern "C" void shib_target_finalize (void)
{
  delete g_shibTargetCCache;

  ShibConfig& shibConf = ShibConfig::getConfig();
  delete shibConf.origin_mapper;
  shibConf.term();

  SAMLConfig& samlConf = SAMLConfig::getConfig();
  samlConf.term();
}

/*
 * shib-resource.cpp -- an interface to Shibboleth Resources (URL applications)
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#ifndef WIN32
# include <unistd.h>
#endif

#include "shib-target.h"

#include <log4cpp/Category.hh>

#include <stdexcept>

using namespace std;
using namespace shibtarget;
using namespace saml;

class shibtarget::ResourcePriv
{
public:
  ResourcePriv(const char *str);
  ~ResourcePriv();

  string m_url;
  string m_resource;
  log4cpp::Category* log;
  vector<SAMLAttribute*> designators;
};

ResourcePriv::ResourcePriv(const char *str)
{
  string ctx = "shibtarget.Resource";
  log = &(log4cpp::Category::getInstance(ctx));

  m_url = str;

  // XXX: The Resource is just the hostname!
  const char* colon=strchr(str,':');
  const char* slash=strchr(colon+3,'/');
  m_resource = m_url.substr(0, slash-str);

  log->info("creating resource: \"%s\" -> \"%s\"", str, m_resource.c_str());

  // Now figure out the designators
  string server = m_url.substr(colon-str+3, slash-(colon+3));

  log->debug("server is \"%s\"", server.c_str());

  ShibTargetConfig& config = ShibTargetConfig::getConfig();
  ShibINI& ini = config.getINI();

  string tag;
  if (ini.get_tag (server, SHIBTARGET_TAG_REQATTRS, true, &tag)) {
    // Now parse the request attributes tag...

    log->debug("Request Attributes: \"%s\"", tag.c_str());

    auto_ptr<char> tag_str(strdup(tag.c_str()));

    char *tags = tag_str.get(), *tagptr = NULL, *the_tag;
    while ((the_tag = strtok_r(tags, " \t\r\n", &tagptr)) != NULL && *the_tag) {

      // Make sure we don't loop ad-infinitum
      tags = NULL;

      log->debug ("Parsed attribute string: \"%s\"", the_tag);
      log->debug ("tagptr = %p", tagptr);
      
      // transcode the attribute string from the tag
      auto_ptr<XMLCh> temp(XMLString::transcode(the_tag));

      // Now create the SAML Attribute from this name
      try {
	SAMLAttribute *attr =
	  new SAMLAttribute(temp.get(),
			    shibboleth::Constants::SHIB_ATTRIBUTE_NAMESPACE_URI);
	if (attr)
	  designators.push_back(attr);
      } catch ( ... ) { }
    }
  } else
    log->debug ("No request-attributes found");
}

ResourcePriv::~ResourcePriv()
{
  for (vector<SAMLAttribute*>::iterator i = designators.begin();
       i != designators.end(); i++)
    delete *i;
}

// Internal Class Definition

Resource::Resource(const char *resource_url)
{
  // XXX: Perform some computation based on the URL...
  m_priv = new ResourcePriv(resource_url);
}

Resource::Resource(string resource_url)
{
  m_priv = new ResourcePriv(resource_url.c_str());
}

Resource::~Resource()
{
  delete m_priv;
}

const char* Resource::getResource() const
{
  return m_priv->m_resource.c_str();
}

const char* Resource::getURL() const
{
  return m_priv->m_url.c_str();
}

bool Resource::equals(Resource* r2) const
{
  return (!strcmp (m_priv->m_url.c_str(), r2->m_priv->m_url.c_str()));
}

Iterator<SAMLAttribute*> Resource::getDesignators() const
{
  return Iterator<SAMLAttribute*>(m_priv->designators);
}

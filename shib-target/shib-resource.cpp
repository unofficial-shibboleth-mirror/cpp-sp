/*
 * shib-resource.cpp -- an interface to Shibboleth Resources (URL applications)
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include <unistd.h>

#include "shib-target.h"

#include <log4cpp/Category.hh>

#include <stdexcept>

using namespace std;
using namespace shibtarget;

class shibtarget::ResourcePriv
{
public:
  ResourcePriv(const char *str);
  ~ResourcePriv();

  string m_url;
  log4cpp::Category* log;
};

ResourcePriv::ResourcePriv(const char *str)
{
  string ctx = "shibtarget.Resource";
  log = &(log4cpp::Category::getInstance(ctx));

  log->info("creating resource: \"%s\"", str);
  m_url = str;
}

ResourcePriv::~ResourcePriv() {}

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

const char* Resource::getResource()
{
  return m_priv->m_url.c_str();
}

bool Resource::equals(Resource* r2)
{
  return (!strcmp (m_priv->m_url.c_str(), r2->m_priv->m_url.c_str()));
}

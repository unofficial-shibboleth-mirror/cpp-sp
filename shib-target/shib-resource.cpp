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
 * shib-resource.cpp -- an interface to Shibboleth Resources (URL applications)
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef WIN32
# define SHIBTARGET_EXPORTS __declspec(dllexport)
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
#ifdef HAVE_STRTOK_R
    while ((the_tag = strtok_r(tags, " \t\r\n", &tagptr)) != NULL && *the_tag) {
#else
    while ((the_tag = strtok(tags, " \t\r\n")) != NULL && *the_tag) {
#endif
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

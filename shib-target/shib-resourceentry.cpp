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
 * shib-resourceentry.cpp: a cached resource entry
 *
 * Created By:  Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include "internal.h"

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_LIBDMALLOCXX
#include <dmalloc.h>
#endif

class shibtarget::ResourceEntryPriv
{
public:
  ResourceEntryPriv();
  ~ResourceEntryPriv();

  SAMLResponse* m_response;
  log4cpp::Category* log;

  time_t createTime;
  int defaultLife;
};

/******************************************************************************/
/* ResourceEntry:  A Credential Cache Entry for a particular Resource URL     */
/******************************************************************************/

ResourceEntryPriv::ResourceEntryPriv() : m_response(NULL), defaultLife(-1)
{
  string ctx = "shibtarget::ResourceEntry";
  log = &(log4cpp::Category::getInstance(ctx));
  createTime = time(NULL);

  // Compute and cache the default life for this Resource Entry
  ShibTargetConfig& config = ShibTargetConfig::getConfig();
  ShibINI& ini = config.getINI();
  string tag;
  if (ini.get_tag (SHIBTARGET_SHAR, SHIBTARGET_TAG_DEFAULTLIFE, true, &tag))
    defaultLife = atoi(tag.c_str());

  if (defaultLife < 0)
    defaultLife = 1800;		// default is 30 minutes
}

ResourceEntryPriv::~ResourceEntryPriv()
{
  if (m_response)
    delete m_response;
}

ResourceEntry::ResourceEntry(const Resource &resource,
			     const SAMLSubject& p_subject,
			     CCache *m_cache,
			     const Iterator<SAMLAuthorityBinding*> AAbindings)
{
  saml::NDC ndc("ResourceEntry()");

  auto_ptr<ResourceEntryPriv> priv(new ResourceEntryPriv());

  auto_ptr<XMLCh> resourceURL(XMLString::transcode(resource.getURL()));

  // Clone the subject...
  // 1) I know the static_cast is safe from clone()
  // 2) the AttributeQuery will destroy this new subject.
  auto_ptr<SAMLSubject> subject(static_cast<SAMLSubject*>(p_subject.clone()));

  // Build a SAML Request....
  SAMLAttributeQuery* q=new SAMLAttributeQuery(subject.get(),resourceURL.get(),
					       resource.getDesignators().clone());
  subject.release();
  auto_ptr<SAMLRequest> req(new SAMLRequest(EMPTY(QName),q));

  // Try this request against all the bindings in the AuthenticationStatement
  // (i.e. send it to each AA in the list of bindings)
  SAMLResponse* response = NULL;
  OriginMetadata site(p_subject.getNameQualifier());
  if (site.fail())
      throw MetadataException("unable to locate origin site's metadata during attribute query");
  auto_ptr<XMLCh> caller(XMLString::transcode(resource.getResource()));
  auto_ptr<SAMLBinding> pBinding(SAMLBindingFactory::getInstance(caller.get(),site));

  while (!response && AAbindings.hasNext()) {
    SAMLAuthorityBinding* binding = AAbindings.next();

    priv->log->debug("Trying binding...");
    priv->log->debug("Sending request");
    response=pBinding->send(*binding,*req);
  }

  // Make sure we got a response
  if (!response) {
    priv->log->info ("No Response");
    throw new ShibTargetException();
  }

  priv->m_response = response;
  m_priv=priv.release();
}

ResourceEntry::~ResourceEntry()
{
  if (m_priv)
    delete m_priv;
}

Iterator<SAMLAssertion*> ResourceEntry::getAssertions()
{
  saml::NDC ndc("getAssertions");
  return m_priv->m_response->getAssertions();
}

bool ResourceEntry::isValid(int slop)
{
  saml::NDC ndc("isValid");

  m_priv->log->info("checking validity");

  // This is awful, but the XMLDateTime class is truly horrible.
  time_t now=time(NULL)+slop;
#ifdef WIN32
  struct tm* ptime=gmtime(&now);
#else
  struct tm res;
  struct tm* ptime=gmtime_r(&now,&res);
#endif
  char timebuf[32];
  strftime(timebuf,32,"%Y-%m-%dT%H:%M:%SZ",ptime);
  auto_ptr<XMLCh> timeptr(XMLString::transcode(timebuf));
  XMLDateTime curDateTime(timeptr.get());
  curDateTime.parseDateTime();

  Iterator<SAMLAssertion*> iter = getAssertions();
  int count = 0;

  while (iter.hasNext()) {
    SAMLAssertion* assertion = iter.next();

    m_priv->log->debug ("testing assertion...");

    const XMLDateTime* thistime = assertion->getNotOnOrAfter();

    // If there is no time, then just continue and ignore this assertion.
    if (! thistime)
      continue;

    count++;
    auto_ptr<char> nowptr(XMLString::transcode(curDateTime.toString()));
    auto_ptr<char> assnptr(XMLString::transcode(thistime->toString()));

    m_priv->log->debug ("comparing now (%s) to %s", nowptr.get(), assnptr.get());
    int result=XMLDateTime::compareOrder(&curDateTime, thistime);

    if (result != XMLDateTime::LESS_THAN) {
      m_priv->log->debug("nope, not still valid");
      return false;
    }
  } // while

  // If we didn't find any assertions with times, then see if we're
  // older than the defaultLife.
  if (!count && (now - m_priv->createTime) > m_priv->defaultLife) {
    m_priv->log->debug("assertion is beyond default life");
    return false;
  }

  m_priv->log->debug("yep, all still valid");
  return true;
}

/*
 * shib-resourceentry.cpp: a cached resource entry
 *
 * Created By:  Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#ifndef WIN32
# include <unistd.h>
#endif

#include "shib-target.h"
#include "ccache-utils.h"

#include <log4cpp/Category.hh>

#ifdef HAVE_LIBDMALLOCXX
#include <dmalloc.h>
#endif

using namespace std;
using namespace saml;
using namespace shibtarget;

class shibtarget::ResourceEntryPriv
{
public:
  ResourceEntryPriv();
  ~ResourceEntryPriv();

  SAMLResponse* m_response;
  log4cpp::Category* log;

  static saml::QName g_respondWith;
};

saml::QName ResourceEntryPriv::g_respondWith(saml::XML::SAML_NS,L(AttributeStatement));

/******************************************************************************/
/* ResourceEntry:  A Credential Cache Entry for a particular Resource URL     */
/******************************************************************************/

ResourceEntryPriv::ResourceEntryPriv() : m_response(NULL)
{
  string ctx = "shibtarget::ResourceEntry";
  log = &(log4cpp::Category::getInstance(ctx));
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

  m_priv = new ResourceEntryPriv();

  auto_ptr<XMLCh> resourceURL(XMLString::transcode(resource.getURL()));
  Iterator<saml::QName> respond_withs = ArrayIterator<saml::QName>(&ResourceEntryPriv::g_respondWith);

  // Clone the subject...
  // 1) I know the static_cast is safe from clone()
  // 2) the AttributeQuery will destroy this new subject.
  SAMLSubject* subject=static_cast<SAMLSubject*>(p_subject.clone());

  // Build a SAML Request....
  SAMLAttributeQuery* q=new SAMLAttributeQuery(subject,resourceURL.get(),
					       resource.getDesignators());
  SAMLRequest* req=new SAMLRequest(respond_withs,q);

  // Try this request against all the bindings in the AuthenticationStatement
  // (i.e. send it to each AA in the list of bindings)
  SAMLResponse* response = NULL;

  while (!response && AAbindings.hasNext()) {
    SAMLAuthorityBinding* binding = AAbindings.next();

    m_priv->log->debug("Trying binding...");
    SAMLBinding* pBinding=m_cache->getBinding(binding->getBinding());
    m_priv->log->debug("Sending request");
    response=pBinding->send(*binding,*req);
  }

  // ok, we can delete the request now.
  delete req;

  // Make sure we got a response
  if (!response) {
    m_priv->log->info ("No Response");
    throw new ShibTargetException();
  }

  m_priv->m_response = response;
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

  while (iter.hasNext()) {
    SAMLAssertion* assertion = iter.next();

    m_priv->log->debug ("testing assertion...");

    const XMLDateTime* thistime = assertion->getNotOnOrAfter();

    if (! thistime) {
      m_priv->log->debug ("getNotOnOrAfter failed.");
      return false;
    }

    auto_ptr<char> nowptr(XMLString::transcode(curDateTime.toString()));
    auto_ptr<char> assnptr(XMLString::transcode(thistime->toString()));

    m_priv->log->debug ("comparing now (%s) to %s", nowptr.get(), assnptr.get());
    int result=XMLDateTime::compareOrder(&curDateTime, thistime);

    if (result != XMLDateTime::LESS_THAN) {
      m_priv->log->debug("nope, not still valid");
      return false;
    }
  } // while

  m_priv->log->debug("yep, all still valid");
  return true;
}

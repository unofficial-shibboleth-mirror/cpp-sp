/*
 * shib-rm.cpp -- Resource Manager interface
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include <unistd.h>

#include "shib-target.h"

#include <xercesc/util/Base64.hpp>
#include <log4cpp/Category.hh>

#include <strstream>
#include <stdexcept>

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

class shibtarget::RMPriv
{
public:
  RMPriv(RPCHandle *rpc, RMConfig cfg);
  ~RMPriv();

  RPCHandle *m_rpc;
  RMConfig m_config;
  log4cpp::Category* log;
};

RMPriv::RMPriv(RPCHandle *rpc, RMConfig cfg)
{
  string ctx = "shibtarget.RM";
  log = &(log4cpp::Category::getInstance(ctx));
  m_rpc = rpc;
  m_config = cfg;
}

RMPriv::~RMPriv() {}

RM::RM(RPCHandle *rpc, RMConfig cfg)
{
  m_priv = new RMPriv(rpc, cfg);
  m_priv->log->info("Created new RM module");
}

RM::~RM()
{
  delete m_priv;
}

RPCError* RM::getAssertions(const char* cookie, const char* ip,
			    const char* url,
			    vector<SAMLAssertion*> &assertions)
{
  saml::NDC ndc("getAssertions");
  m_priv->log->info ("get assertions...");

  if (!cookie || *cookie == '\0') {
    m_priv->log->error ("no cookie");
    return new RPCError(-1, "No such cookie");
  }

  if (!ip) {
    m_priv->log->error ("no ip address");
    return new RPCError(-1, "No IP Address");
  }

  if (!url || *url == '\0') {
    m_priv->log->error ("no URL");
    return new RPCError(-1, "Invalid URL Resource");
  }

  m_priv->log->info ("request from %s for \"%s\"", ip, url);
  m_priv->log->debug ("session cookie: %s", cookie);

  shibrpc_get_assertions_args_1 arg;
  arg.cookie.cookie = (char*)cookie;
  arg.cookie.client_addr = (char*)ip;
  arg.checkIPAddress = m_priv->m_config.checkIPAddress;
  arg.url = (char *)url;

  shibrpc_get_assertions_ret_1 ret;
  memset (&ret, 0, sizeof(ret));

  // Loop on the RPC in case we lost contact the first time through
  int retry = 1;
  CLIENT *clnt;
  do {
    clnt = m_priv->m_rpc->connect();
    if (shibrpc_get_assertions_1 (&arg, &ret, clnt) != RPC_SUCCESS) {
      m_priv->m_rpc->disconnect();
      if (retry)
	retry--;
      else {
	m_priv->log->error ("RPC Failure");
	return new RPCError(-1, "RPC Failure");
      }
    } else
      retry = -1;
  } while (retry >= 0);

  m_priv->log->debug ("RPC completed with status %d", ret.status);

  RPCError* retval = NULL;
  if (ret.status)
    retval = new RPCError(ret.status, ret.error_msg);
  else {
    for (u_int i = 0; i < ret.assertions.assertions_len; i++) {
      istrstream attrstream(ret.assertions.assertions_val[i].assertion);
      SAMLAssertion *as = NULL;
      try {
	m_priv->log->debug("Trying to decode assertion %d: %s", i,
			   ret.assertions.assertions_val[i].assertion);
	as = new SAMLAssertion(attrstream);
      } catch (SAMLException& e) {
	m_priv->log->error ("SAML Exception: %s", e.what());
	throw;
      } catch (XMLException& e) {
	m_priv->log->error ("XML Exception: %s", e.getMessage());
	throw;
      }

      if (as)
	assertions.push_back(as);
    }

    if (!retval)
      retval = new RPCError();
  }

  clnt_freeres (clnt, (xdrproc_t)xdr_shibrpc_get_assertions_ret_1, (caddr_t)&ret);

  m_priv->log->debug ("returning..");
  return retval;
}

void RM::serialize(SAMLAssertion &assertion, string &result)
{
  saml::NDC ndc("RM::serialize");

  ostrstream os;
  os << assertion;
  unsigned int outlen;
  XMLByte* serialized = Base64::encode(reinterpret_cast<XMLByte*>(os.str()),
				       os.pcount(), &outlen);
  result = (char*) serialized;
}

Iterator<SAMLAttribute*> RM::getAttributes(SAMLAssertion &assertion)
{
  static vector<SAMLAttribute*> emptyVector;

  // XXX: Only deal with a single statement!!!!
  Iterator<SAMLStatement*> i = assertion.getStatements();
  if (i.hasNext()) {
    SAMLAttributeStatement* s = static_cast<SAMLAttributeStatement*>(i.next());

    if (s)
      return s->getAttributes();
  }
  
  return Iterator<SAMLAttribute*>(emptyVector);
}

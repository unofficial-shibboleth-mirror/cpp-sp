/*
 * shib-rm.cpp -- Resource Manager interface
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#ifndef WIN32
# include <unistd.h>
#endif

#include "shib-target.h"

#include <xercesc/util/Base64.hpp>
#include <log4cpp/Category.hh>

#include <sstream>
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
			    vector<SAMLAssertion*> &assertions,
			    SAMLAuthenticationStatement **statement)
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
      // FAILED.  Release, disconnect, and try again.
      m_priv->m_rpc->release();
      m_priv->m_rpc->disconnect();
      if (retry)
	retry--;
      else {
	m_priv->log->error ("RPC Failure");
	return new RPCError(-1, "RPC Failure");
      }
    } else {
      // SUCCESS.  Release the lock.
      m_priv->m_rpc->release();
      retry = -1;
    }
  } while (retry >= 0);

  m_priv->log->debug ("RPC completed with status %d", ret.status);

  RPCError* retval = NULL;
  if (ret.status)
    retval = new RPCError(ret.status, ret.error_msg);
  else {
    for (u_int i = 0; i < ret.assertions.assertions_len; i++) {
      istringstream attrstream(ret.assertions.assertions_val[i].xml_string);
      SAMLAssertion *as = NULL;
      try {
//	m_priv->log->debug("Trying to decode assertion %d: %s", i,
//			   ret.assertions.assertions_val[i].xml_string);
        m_priv->log->debugStream() << "Trying to decode assertion " << i
            << ": " << ret.assertions.assertions_val[i].xml_string << log4cpp::CategoryStream::ENDLINE;
	as = new SAMLAssertion(attrstream);
      } catch (SAMLException& e) {
	m_priv->log->error ("SAML Exception: %s", e.what());
	throw;
      } catch (XMLException& e) {
	m_priv->log->error ("XML Exception: %s", e.getMessage());
	throw;
      }

      if (as)
      {
        // XXX: Should move this audience check up to the RPC server side, and cache each assertion one
        // by one instead of the whole response.
        bool ok=true;
        Iterator<SAMLCondition*> conds=as->getConditions();
        while (conds.hasNext())
        {
            SAMLAudienceRestrictionCondition* cond=dynaptr(SAMLAudienceRestrictionCondition,conds.next());
            if (!cond->eval(ShibTargetConfig::getConfig().getPolicies()))
            {
                m_priv->log->warn("Assertion failed AudienceRestrictionCondition check, skipping it...");
                ok=false;
            }
        }
        if (ok)
	        assertions.push_back(as);
      }

      // return the Authentication Statement
      if (statement) {
	istringstream authstream(ret.auth_statement.xml_string);
	SAMLAuthenticationStatement *auth = NULL;
	try {
	  m_priv->log->debugStream() <<
	    "Trying to decode authentication statement: " <<
	    ret.auth_statement.xml_string << log4cpp::CategoryStream::ENDLINE;
	  auth = new SAMLAuthenticationStatement(authstream);
	} catch (SAMLException &e) {
	  m_priv->log->error ("SAML Exception: %s", e.what());
	  throw;
	} catch (XMLException &e) {
	  m_priv->log->error ("XML Exception: %s", e.getMessage());
	  throw;
	}

	// Save off the statement
	*statement = auth;
      }
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

  ostringstream os;
  os << assertion;
  unsigned int outlen;
  char* assn = (char*) os.str().c_str();
  XMLByte* serialized = Base64::encode(reinterpret_cast<XMLByte*>(assn),
				       os.str().length(), &outlen);
  result = (char*) serialized;
}

Iterator<SAMLAttribute*> RM::getAttributes(SAMLAssertion &assertion)
{
  static vector<SAMLAttribute*> emptyVector;

  // XXX: Only deal with a single statement!!!!
  Iterator<SAMLStatement*> i = assertion.getStatements();
  if (i.hasNext()) {
    SAMLAttributeStatement* s =
       static_cast<SAMLAttributeStatement*>(const_cast<SAMLStatement*>(i.next()));

    if (s)
      return s->getAttributes();
  }
  
  return Iterator<SAMLAttribute*>(emptyVector);
}

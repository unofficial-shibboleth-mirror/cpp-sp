/*
 * shib-rm.cpp -- Resource Manager interface
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include <unistd.h>

#include "shib-target.h"

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

RPCError* RM::getAttributes(const char* cookie, const char* ip,
			   Resource *resource,
			   vector<saml::QName*> attr_requests,
			   vector<SAMLAttribute*> &attr_replies,
			   string &assertion)
{
  saml::NDC ndc("getAttributes");
  m_priv->log->info ("get attributes...");

  if (!cookie || *cookie == '\0') {
    m_priv->log->error ("no cookie");
    return new RPCError(-1, "No such cookie");
  }

  if (!ip) {
    m_priv->log->error ("no ip address");
    return new RPCError(-1, "No IP Address");
  }

  if (!resource) {
    m_priv->log->error ("no resource");
    return new RPCError(-1, "Invalid Resource");
  }

  m_priv->log->info ("request from %s for \"%s\"", ip, resource->getResource());
  m_priv->log->debug ("session cookie: %s", cookie);

  shibrpc_get_attrs_args_1 arg;
  arg.cookie.cookie = (char*)cookie;
  arg.cookie.client_addr = (char*)ip;
  arg.checkIPAddress = m_priv->m_config.checkIPAddress;
  arg.url = (char *)(resource->getResource());
  arg.attr_reqs.attr_reqs_len = 0;
  arg.attr_reqs.attr_reqs_val = NULL;

  shibrpc_get_attrs_ret_1 ret;
  memset (&ret, 0, sizeof(ret));

  // Loop on the RPC in case we lost contact the first time through
  int retry = 1;
  CLIENT *clnt;
  do {
    clnt = m_priv->m_rpc->connect();
    if (shibrpc_get_attrs_1 (&arg, &ret, clnt) != RPC_SUCCESS) {
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
    for (u_int i = 0; i < ret.attr_reps.attr_reps_len; i++) {
      istrstream attrstream(ret.attr_reps.attr_reps_val[i].rep);
      SAMLAttribute *attr = NULL;
      try {
	m_priv->log->debug("Trying to decode attribute %d: %s", i,
			   ret.attr_reps.attr_reps_val[i].rep);
	attr = new SAMLAttribute(attrstream);
      } catch (XMLException& e) {
	m_priv->log->error ("XML Exception: %s", e.getMessage());
	throw;
      }

      if (attr)
	attr_replies.push_back(attr);
    }
    if (!retval) {
      retval = new RPCError();
      assertion = ret.assertion;
    }
  }

  clnt_freeres (clnt, (xdrproc_t)xdr_shibrpc_get_attrs_ret_1, (caddr_t)&ret);

  m_priv->log->debug ("returning..");
  return retval;
}

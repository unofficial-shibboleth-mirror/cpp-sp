/*
 * shib-shire.cpp -- Shibboleth SHIRE functions
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
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

class shibtarget::SHIREPriv
{
public:
  SHIREPriv(RPCHandle *rpc, SHIREConfig cfg, string shire_url);
  ~SHIREPriv();

  RPCHandle *	m_rpc;
  SHIREConfig	m_config;
  string	m_url;

  log4cpp::Category* log;
};

SHIREPriv::SHIREPriv(RPCHandle *rpc, SHIREConfig cfg, string shire_url)
{
  string ctx = "shibtarget.SHIRE";
  log = &(log4cpp::Category::getInstance(ctx));
  m_rpc = rpc;
  m_config = cfg;
  m_url = shire_url;
}

SHIREPriv::~SHIREPriv() {}


SHIRE::SHIRE(RPCHandle *rpc, SHIREConfig cfg, string shire_url)
{
  m_priv = new SHIREPriv(rpc, cfg, shire_url);
  m_priv->log->info ("New SHIRE handle created");
}

SHIRE::~SHIRE()
{
  delete m_priv;
}


RPCError* SHIRE::sessionIsValid(const char* cookie, const char* ip, const char* url)
{
  saml::NDC ndc("sessionIsValid");

  if (!cookie || *cookie == '\0') {
    m_priv->log->error ("No cookie");
    return new RPCError(-1, "No such cookie");
  }

  if (!ip) {
    m_priv->log->error ("No IP");
    return new RPCError(-1, "Invalid IP Address");
  }

  // make sure we pass _something_ to the server
  if (!url) url = "";

  m_priv->log->info ("is session valid: %s", ip);
  m_priv->log->debug ("session cookie: %s", cookie);

  shibrpc_session_is_valid_args_1 arg;

  arg.cookie.cookie = (char*)cookie;
  arg.cookie.client_addr = (char *)ip;
  arg.url = (char *)url;
  arg.lifetime = m_priv->m_config.lifetime;
  arg.timeout = m_priv->m_config.timeout;
  arg.checkIPAddress = m_priv->m_config.checkIPAddress;

  shibrpc_session_is_valid_ret_1 ret;
  memset (&ret, 0, sizeof(ret));

  // Loop on the RPC in case we lost contact the first time through
  int retry = 1;
  CLIENT *clnt;
  do {
    clnt = m_priv->m_rpc->connect();
    if (shibrpc_session_is_valid_1 (&arg, &ret, clnt) != RPC_SUCCESS) {
      // FAILED.  Release, disconnect, and try again...
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

  RPCError* retval;
  if (ret.status)
    retval = new RPCError(ret.status, ret.error_msg);
  else
    retval = new RPCError();

  clnt_freeres (clnt, (xdrproc_t)xdr_shibrpc_session_is_valid_ret_1, (caddr_t)&ret);

  m_priv->log->debug ("returning");
  return retval;
}

RPCError* SHIRE::sessionCreate(const char* post, const char* ip, string& cookie)
{
  saml::NDC ndc("sessionCreate");

  if (!post || *post == '\0') {
    m_priv->log->error ("No POST");
    return new RPCError(-1,  "Invalid POST string");
  }

  if (!ip) {
    m_priv->log->error ("No IP");
    return new RPCError(-1, "Invalid IP Address");
  }

  m_priv->log->info ("create session for user at %s", ip);

  shibrpc_new_session_args_1 arg;
  arg.shire_location = (char*) (m_priv->m_url.c_str());
  arg.saml_post = (char*)post;
  arg.client_addr = (char*)ip;
  arg.checkIPAddress = m_priv->m_config.checkIPAddress;

  shibrpc_new_session_ret_1 ret;
  memset (&ret, 0, sizeof(ret));

  // Loop on the RPC in case we lost contact the first time through
  int retry = 1;
  CLIENT* clnt;
  do {
    clnt = m_priv->m_rpc->connect();
    if (shibrpc_new_session_1 (&arg, &ret, clnt) != RPC_SUCCESS) {
      // FAILED.  Release, disconnect, and retry
      m_priv->m_rpc->release();
      m_priv->m_rpc->disconnect();
      if (retry)
	retry--;
      else {
	m_priv->log->error ("RPC Failure");
	return new RPCError(-1, "RPC Failure");
      }
    } else {
      // SUCCESS.  Release and continue
      m_priv->m_rpc->release();
      retry = -1;
    }
  } while (retry >= 0);

  m_priv->log->debug ("RPC completed with status %d", ret.status);

  RPCError* retval;
  if (ret.status)
    retval = new RPCError(ret.status, ret.error_msg);
  else {
    m_priv->log->debug ("new cookie: %s", ret.cookie);
    cookie = ret.cookie;
    retval = new RPCError();
  }

  clnt_freeres (clnt, (xdrproc_t)xdr_shibrpc_new_session_ret_1, (caddr_t)&ret);

  m_priv->log->debug ("returning");
  return retval;
}

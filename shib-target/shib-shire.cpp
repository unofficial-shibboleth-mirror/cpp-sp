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
 * shib-shire.cpp -- Shibboleth SHIRE functions
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include "internal.h"

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <stdexcept>

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
  m_priv->log->info ("New SHIRE handle created: %p", m_priv);
}

SHIRE::~SHIRE()
{
  delete m_priv;
}


RPCError* SHIRE::sessionIsValid(const char* cookie, const char* ip, const char* url)
{
  saml::NDC ndc("sessionIsValid");

  if (!cookie || *cookie == '\0') {
    m_priv->log->error ("No cookie value was provided");
    return new RPCError(SHIBRPC_NO_SESSION, "No cookie value was provided");
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
      m_priv->log->debug ("RPC Failure: %p (%p): %s", m_priv, clnt,
			  clnt_spcreateerror (""));
      m_priv->m_rpc->release();
      m_priv->m_rpc->disconnect();
      if (retry)
	retry--;
      else {
	m_priv->log->error ("RPC Failure: %p (%p)", m_priv, clnt);
	return new RPCError(-1, "RPC Failure");
      }
    } else {
      // SUCCESS.  Release the lock.
      m_priv->m_rpc->release();
      retry = -1;
    }
  } while (retry >= 0);

  m_priv->log->debug ("RPC completed with status %d, %p", ret.status.status, m_priv);

  RPCError* retval;
  if (ret.status.status)
    retval = new RPCError(&ret.status);
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
      m_priv->log->debug ("RPC Failure: %p (%p): %s", m_priv, clnt,
			  clnt_spcreateerror (""));
      m_priv->m_rpc->release();
      m_priv->m_rpc->disconnect();
      if (retry)
	retry--;
      else {
	m_priv->log->error ("RPC Failure: %p (%p)", m_priv, clnt);
	return new RPCError(-1, "RPC Failure");
      }
    } else {
      // SUCCESS.  Release and continue
      m_priv->m_rpc->release();
      retry = -1;
    }
  } while (retry >= 0);

  m_priv->log->debug ("RPC completed with status %d (%p)", ret.status.status, m_priv);

  RPCError* retval;
  if (ret.status.status)
    retval = new RPCError(&ret.status);
  else {
    m_priv->log->debug ("new cookie: %s", ret.cookie);
    cookie = ret.cookie;
    retval = new RPCError();
  }

  clnt_freeres (clnt, (xdrproc_t)xdr_shibrpc_new_session_ret_1, (caddr_t)&ret);

  m_priv->log->debug ("returning");
  return retval;
}

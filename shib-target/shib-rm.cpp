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
 * shib-rm.cpp -- Resource Manager interface
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include "internal.h"

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <xercesc/util/Base64.hpp>
#include <log4cpp/Category.hh>

#include <sstream>
#include <stdexcept>

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
      m_priv->log->debug ("RPC Failure: %p (%p): %s", m_priv, clnt,
			  clnt_spcreateerror (""));
      m_priv->m_rpc->release();
      m_priv->m_rpc->disconnect();
      if (retry)
	retry--;
      else {
	m_priv->log->error ("RPC Failure: %p, %p", m_priv, clnt);
	return new RPCError(-1, "RPC Failure");
      }
    } else {
      // SUCCESS.  Release the lock.
      m_priv->m_rpc->release();
      retry = -1;
    }
  } while (retry >= 0);

  m_priv->log->debug ("RPC completed with status %d (%p)", ret.status.status, m_priv);

  RPCError* retval = NULL;
  if (ret.status.status)
    retval = new RPCError(&ret.status);
  else {
    try {
      try {
	for (u_int i = 0; i < ret.assertions.assertions_len; i++) {
	  istringstream attrstream(ret.assertions.assertions_val[i].xml_string);
	  SAMLAssertion *as = NULL;
	  //	m_priv->log->debug("Trying to decode assertion %d: %s", i,
	  //			   ret.assertions.assertions_val[i].xml_string);
	  m_priv->log->debugStream() << "Trying to decode assertion " << i
		     << ": " << ret.assertions.assertions_val[i].xml_string <<
	    		log4cpp::CategoryStream::ENDLINE;
	  as = new SAMLAssertion(attrstream);

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
	}

	// return the Authentication Statement
	if (statement) {
	  istringstream authstream(ret.auth_statement.xml_string);
	  SAMLAuthenticationStatement *auth = NULL;
	  
	  m_priv->log->debugStream() <<
	    "Trying to decode authentication statement: " <<
	    ret.auth_statement.xml_string << log4cpp::CategoryStream::ENDLINE;
	  auth = new SAMLAuthenticationStatement(authstream);

	  // Save off the statement
	  *statement = auth;
	}

      } catch (SAMLException& e) {
	m_priv->log->error ("SAML Exception: %s", e.what());
	ostringstream os;
	os << e;
	throw ShibTargetException(SHIBRPC_SAML_EXCEPTION, os.str());
      } catch (XMLException& e) {
	m_priv->log->error ("XML Exception: %s", e.getMessage());
	auto_ptr<char> msg(XMLString::transcode(e.getMessage()));
	throw ShibTargetException (SHIBRPC_XML_EXCEPTION, msg.get());
      }
    } catch (ShibTargetException &e) {
      retval = new RPCError(e);
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
  XMLString::release(&serialized);
}

Iterator<SAMLAttribute*> RM::getAttributes(SAMLAssertion &assertion)
{
  // XXX: Only deal with a single statement!!!!
  Iterator<SAMLStatement*> i = assertion.getStatements();
  if (i.hasNext()) {
    SAMLAttributeStatement* s =
       static_cast<SAMLAttributeStatement*>(const_cast<SAMLStatement*>(i.next()));

    if (s)
      return s->getAttributes();
  }
  
  return EMPTY(SAMLAttribute*);
}

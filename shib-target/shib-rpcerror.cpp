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
 * shib-rpcerror.cpp -- RPC Error class
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
#include <sstream>
#include <typeinfo>
#include <log4cpp/Category.hh>

using namespace std;
using namespace log4cpp;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

namespace {
  int initializing = 0;
  int initialized = 0;
  const type_info* type_MalformedException = NULL;
  const type_info* type_UnsupportedExtensionException = NULL;
  const type_info* type_InvalidCryptoException = NULL;
  const type_info* type_TrustException = NULL;
  const type_info* type_BindingException = NULL;
  const type_info* type_SOAPException = NULL;
  const type_info* type_ContentTypeException = NULL;

  const type_info* type_ProfileException = NULL;
  const type_info* type_FatalProfileException = NULL;
  const type_info* type_RetryableProfileException = NULL;
  const type_info* type_ExpiredAssertionException = NULL;
  const type_info* type_InvalidAssertionException = NULL;
  const type_info* type_ReplayedAssertionException = NULL;

  const XMLCh code_InvalidHandle[] = // InvalidHandle
    { chLatin_I, chLatin_n, chLatin_v, chLatin_a, chLatin_l, chLatin_i, chLatin_d,
      chLatin_H, chLatin_a, chLatin_n, chLatin_d, chLatin_l, chLatin_e, 
      chNull
    };
}

void rpcerror_init (void)
{
  if (initialized)
    return;

  if (initializing++) {
    while (!initialized);
    return;
  }

  type_MalformedException = &typeid(MalformedException);
  type_UnsupportedExtensionException = &typeid(UnsupportedExtensionException);
  type_InvalidCryptoException = &typeid(InvalidCryptoException);
  type_TrustException = &typeid(TrustException);
  type_BindingException = &typeid(BindingException);
  type_SOAPException = &typeid(SOAPException);
  type_ContentTypeException = &typeid(ContentTypeException);

  type_ProfileException = &typeid(ProfileException);
  type_FatalProfileException = &typeid(FatalProfileException);
  type_RetryableProfileException = &typeid(RetryableProfileException);
  type_ExpiredAssertionException = &typeid(ExpiredAssertionException);
  type_InvalidAssertionException = &typeid(InvalidAssertionException);
  type_ReplayedAssertionException = &typeid(ReplayedAssertionException);

  initialized = 1;
}

#define TEST_TYPE(type,str) { if (type && *type == info) return str; }
const char* rpcerror_exception_type(SAMLException* e)
{
  if (!e)
    return "Invalid (NULL) exception";

  const type_info& info = typeid(*e);

  TEST_TYPE(type_MalformedException, "Exception: XML object is malformed");
  TEST_TYPE(type_UnsupportedExtensionException,
	    "Exception: an unsupported extention was accessed");
  TEST_TYPE(type_InvalidCryptoException, "Exception: cryptographic check failed");
  TEST_TYPE(type_TrustException, "Exception: trust failed");
  TEST_TYPE(type_BindingException,
	    "Exception: an error occurred in binding to the AA");
  TEST_TYPE(type_SOAPException, "Exception: SOAP error");
  TEST_TYPE(type_ContentTypeException, "Exception: Content Type Failure");

  TEST_TYPE(type_ProfileException, "Exception: Profile Error");
  TEST_TYPE(type_FatalProfileException, "Exception: Fatal Profile Error");
  TEST_TYPE(type_RetryableProfileException, "Exception: Retryable Profile Error");
  TEST_TYPE(type_ExpiredAssertionException, "Exception: Expired Assertion");
  TEST_TYPE(type_InvalidAssertionException, "Exception: Invalid Assertion");
  TEST_TYPE(type_ReplayedAssertionException, "Exception: Replayed Assertion");

  return "Unknown SAML Exception";
}
#undef TEST_TYPE

class shibtarget::RPCErrorPriv {
public:
  RPCErrorPriv(int stat, const char* msg, const XMLCh* originSite);
  ~RPCErrorPriv();

  int		status;
  string	error_msg;
  XMLCh*	origin;
  SAMLException* except;
};

RPCErrorPriv::RPCErrorPriv(int stat, const char* msg, const XMLCh* originSite)
{
  status = stat;
  string ctx = "shibtarget.RPCErrorPriv";
  log4cpp::Category& log = log4cpp::Category::getInstance(ctx);

  rpcerror_init();

  origin = XMLString::replicate(originSite);

  if (status == SHIBRPC_SAML_EXCEPTION) {
    istringstream estr(msg);
    try { 
      except = NULL;
      except = SAMLException::getInstance(estr);
    } catch (SAMLException& e) {
      log.error ("Caught SAML Exception while building the SAMLException: %s",
		 e.what());
      log.error ("XML: %s", msg);
    } catch (XMLException& e) {
      log.error ("Caught XML Exception building SAMLException: %s",
		 e.getMessage());
      log.error ("XML: %s", msg);
    } catch (...) {
      log.error ("Caught exception building SAMLException!");
      log.error ("XML: %s", msg);
    }
    if (dynamic_cast<ContentTypeException*>(except)!=NULL)
        error_msg = 
	  "We were unable to contact your identity provider and cannot grant "
	  "access at this time. Please contact your provider's help desk or "
	  "administrator so that the appropriate steps can be taken.  "
	  "Be sure to describe what you're trying to access and useful "
	  "context like the current time.";
    else
        error_msg = (except ? except->what() : msg);
  } else {
    error_msg = msg;
    except = NULL;
  }
}

RPCErrorPriv::~RPCErrorPriv()
{
  if (except)
    delete except;
  if (origin)
      XMLString::release(&origin);
}

RPCError::RPCError(ShibRpcError* error)
{
  if (!error || !error->status)
    init(0, "", NULL);
  else {
    auto_ptr_XMLCh origin(error->ShibRpcError_u.e.origin);
    init(error->status, error->ShibRpcError_u.e.error, origin.get());
  }
}

void RPCError::init(int stat, char const* msg, const XMLCh* origin)
{
  m_priv = new RPCErrorPriv(stat,msg,origin);
}

RPCError::~RPCError()
{
  delete m_priv;
}

bool RPCError::isError() { return (m_priv->status != 0); }

#define TEST_TYPE(type) { if (type && *type == info) return true; }
bool RPCError::isRetryable()
{
  switch (m_priv->status) {
  case SHIBRPC_NO_SESSION:
  case SHIBRPC_SESSION_EXPIRED:
    return true;

  case SHIBRPC_SAML_EXCEPTION:
    if (m_priv->except) {
      const type_info& info = typeid(*m_priv->except);

      TEST_TYPE(type_RetryableProfileException);
      //TEST_TYPE(type_ExpiredAssertionException);

      Iterator<saml::QName> codes = m_priv->except->getCodes();
      while (codes.hasNext()) {
	saml::QName name = codes.next();

	if (!XMLString::compareString(name.getNamespaceURI(),
				      shibboleth::Constants::SHIB_NS)) {
	  if (!XMLString::compareString(name.getLocalName(), code_InvalidHandle)) {
	    return true;
	  }
	}
      }
    }

    // FALLTHROUGH
  default:
    return false;
  }
}
#undef TEST_TYPE

const char* RPCError::getType()
{
  switch (m_priv->status) {
  case SHIBRPC_OK:		return "No Error";
  case SHIBRPC_UNKNOWN_ERROR:	return "Unknown error";
  case SHIBRPC_INTERNAL_ERROR:	return "Internal Error";
  case SHIBRPC_XML_EXCEPTION:	return "Xerces XML Exception";
  case SHIBRPC_SAX_EXCEPTION:	return "Xerces SAX Exception";
  case SHIBRPC_SAML_EXCEPTION:	return rpcerror_exception_type(m_priv->except);

  case SHIBRPC_NO_SESSION:	return "No Session";
  case SHIBRPC_SESSION_EXPIRED:	return "Session Expired";
  case SHIBRPC_IPADDR_MISMATCH:	return "IP Address Mismatch";

  case SHIBRPC_IPADDR_MISSING:	return "IP Address Missing";
  case SHIBRPC_RESPONSE_MISSING:	return "SAML Response Missing";
  case SHIBRPC_ASSERTION_REPLAYED:	return "SAML Assertion Replayed";
  default:			return "Unknown Shibboleth RPC error";
  }
}

const char* RPCError::getText()
{
  return m_priv->error_msg.c_str();
}

const char* RPCError::getDesc()
{
  if (m_priv->except) {
    Iterator<saml::QName> i=m_priv->except->getCodes();
    if (i.hasNext() &&
	XMLString::compareString(L(Responder),i.next().getLocalName()))
      return
	"An error occurred at the target system while processing your request";
    else
      return "An error occurred at your origin site while processing your request";
  } else
    return "An error occurred processing your request";
}

int RPCError::getCode() { return m_priv->status; }

string RPCError::getOriginErrorURL()
{
    if (m_priv->origin) {
        Metadata mapper(ShibTargetConfig::getConfig().getMetadataProviders());
        const IProvider* provider=mapper.lookup(m_priv->origin);
        if (provider) {
            Iterator<const IProviderRole*> roles=provider->getRoles();
            while (roles.hasNext()) {
            const char* temp=roles.next()->getErrorURL();
            if (temp)
                return temp;
            }
        }
    }
    return "No URL Available";
}

string RPCError::getOriginContactName()
{ 
    if (m_priv->origin) {
        Metadata mapper(ShibTargetConfig::getConfig().getMetadataProviders());
        const IProvider* provider=mapper.lookup(m_priv->origin);
        Iterator<const IContactPerson*> i=provider ? provider->getContacts() : EMPTY(const IContactPerson*);
        while (i.hasNext()) {
            const IContactPerson* c=i.next();
            if ((c->getType()==IContactPerson::technical || c->getType()==IContactPerson::support) && c->getName())
                return c->getName();
        }
    }
    return "No Name Available";
}

string RPCError::getOriginContactEmail()
{
    if (m_priv->origin) {
        Metadata mapper(ShibTargetConfig::getConfig().getMetadataProviders());
        const IProvider* provider=mapper.lookup(m_priv->origin);
        Iterator<const IContactPerson*> i=provider ? provider->getContacts() : EMPTY(const IContactPerson*);
        while (i.hasNext()) {
            const IContactPerson* c=i.next();
            if (c->getType()==IContactPerson::technical || c->getType()==IContactPerson::support) {
                Iterator<string> emails=c->getEmails();
                if (emails.hasNext())
                    return emails.next();
            }
        }
    }
    return "No Email Available";
}

/*
 * shib-rpcerror.cpp -- RPC Error class
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#ifndef WIN32
# include <unistd.h>
#endif

#include "shib-target.h"

#include <stdexcept>
#include <sstream>
#include <typeinfo>

#include <log4cpp/Category.hh>

using namespace std;
using namespace shibtarget;
using namespace saml;

namespace {
  int initializing = 0;
  int initialized = 0;
  const type_info* type_MalformedException = NULL;
  const type_info* type_UnsupportedExtensionException = NULL;
  const type_info* type_InvalidCryptoException = NULL;
  const type_info* type_TrustException = NULL;
  const type_info* type_BindingException = NULL;
  const type_info* type_SOAPException = NULL;
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

  return "Unknown SAML Exception";
}

void RPCError::init(int stat, char const* msg)
{
  status = stat;
  string ctx = "shibtarget.RPCError";
  log4cpp::Category& log = log4cpp::Category::getInstance(ctx);

  rpcerror_init();

  if (status == SHIBRPC_SAML_EXCEPTION) {
    istringstream estr(msg);
    try { 
      m_except = NULL;
      m_except = SAMLException::getInstance(estr);
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
    error_msg = (m_except ? m_except->what() : msg);
  } else {
    error_msg = msg;
    m_except = NULL;
  }
}

RPCError::~RPCError() 
{
  if (m_except)
    delete m_except;
}

const char* RPCError::toString()
{
  switch (status) {
  case SHIBRPC_OK:		return "No Error";
  case SHIBRPC_UNKNOWN_ERROR:	return "Unknown error";
  case SHIBRPC_IPADDR_MISMATCH:	return "IP Address Mismatch";
  case SHIBRPC_NO_SESSION:	return "No Session";
  case SHIBRPC_XML_EXCEPTION:	return "Xerces XML Exception";
  case SHIBRPC_SAML_EXCEPTION:	return rpcerror_exception_type(m_except);
  case SHIBRPC_INTERNAL_ERROR:	return "Internal Error";
  case SHIBRPC_SAX_EXCEPTION:	return "Xerces SAX Exception";
  case SHIBRPC_SESSION_EXPIRED:	return "Session Expired";
  case SHIBRPC_AUTHSTATEMENT_MISSING:	return "Authentication Statement Missing";
  case SHIBRPC_IPADDR_MISSING:	return "IP Address Missing";
  case SHIBRPC_RESPONSE_MISSING:	return "SAML Response Missing";
  case SHIBRPC_ASSERTION_MISSING:	return "SAML Assertion Missing";
  case SHIBRPC_ASSERTION_REPLAYED:	return "SAML Assertion Replayed";
  default:			return "Unknown Shibboleth RPC error";
  }
}

bool RPCError::isRetryable()
{
  switch (status) {
  case SHIBRPC_NO_SESSION:
  case SHIBRPC_SESSION_EXPIRED:
    return true;

  case SHIBRPC_SAML_EXCEPTION:
  {
    const char* msg = (m_except ? m_except->what() : "");
    if (!strcmp(msg, "SAMLPOSTProfile::accept() detected expired response"))
      return true;
  }

  default:
    return false;
  }
}


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
using namespace shibboleth;
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
  xstring	origin;
  SAMLException* except;
};

RPCErrorPriv::RPCErrorPriv(int stat, const char* msg, const XMLCh* originSite)
{
  status = stat;
  string ctx = "shibtarget.RPCErrorPriv";
  log4cpp::Category& log = log4cpp::Category::getInstance(ctx);

  rpcerror_init();

  if (originSite) origin = originSite;

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
    if (dynaptr(ContentTypeException, except)!=NULL)
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
}

RPCError::RPCError(ShibRpcError* error)
{
  if (!error || !error->status)
    init(0, "", NULL);
  else {
    auto_ptr<XMLCh> origin(XMLString::transcode(error->ShibRpcError_u.e.origin));
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
      TEST_TYPE(type_ExpiredAssertionException);

      Iterator<saml::QName> codes = m_priv->except->getCodes();
      while (codes.hasNext()) {
	saml::QName name = codes.next();

	if (!XMLString::compareString(name.getNamespaceURI(),
				      shibboleth::XML::SHIB_NS)) {
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

typedef const char* (OriginSiteMapper::* Pmember)(const XMLCh*) const;
const char* get_mapper_string(const char* defaultStr, Pmember fcn,
			      const XMLCh* originSite)
{
  const char* res = NULL;

  if (originSite) {
    OriginSiteMapper mapper;
    res = (mapper.*fcn)(originSite);
  }

  if (res && *res)
    return res;

  return defaultStr;
}

const char* RPCError::getOriginErrorURL()
{
  return get_mapper_string("No URL Available", &OriginSiteMapper::getErrorURL,
			   m_priv->origin.c_str());
}

const char* RPCError::getOriginContactName()
{ 
  return get_mapper_string("No Name Available", &OriginSiteMapper::getContactName,
			   m_priv->origin.c_str());
}

const char* RPCError::getOriginContactEmail()
{
  return get_mapper_string("No Email Available", &OriginSiteMapper::getContactEmail,
			   m_priv->origin.c_str());
}

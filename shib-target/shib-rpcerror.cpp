/*
 * shib-rpcerror.cpp -- RPC Error class
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include <unistd.h>

#include "shib-target.h"

#include <stdexcept>
#include <strstream>

#include <log4cpp/Category.hh>

using namespace std;
using namespace shibtarget;
using namespace saml;


void RPCError::init(int stat, char const* msg)
{
  status = stat;
  string ctx = "shibtarget.RPCError";
  log4cpp::Category& log = log4cpp::Category::getInstance(ctx);

  if (status == SHIBRPC_SAML_EXCEPTION) {
    istrstream estr(msg);
    try { 
      m_except = NULL;
      m_except = new SAMLException(estr);
    } catch (SAMLException& e) {
      log.error ("Caught SAML Exception while building the SAMLException: %s",
		 e.what());
      log.error ("XML: %s", msg);
    } catch (SAXException& e) {
      ostrstream os;
      xmlout(os, e.getMessage());
      log.error ("Caught SAX Exception building SAMLException: %s", os.str());
      log.error ("XML: %s", msg);
    } catch (XMLException& e) {
      log.error ("Caught XML Exception building SAMLException: %s",
		 e.getMessage());
      log.error ("XML: %s", msg);
    } catch (...) {
      log.error ("Caught exception building SAMLException!");
      log.error ("XML: %s", msg);
    }
    error_msg = "";
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

string RPCError::getHTML()
{
  string retval;

  switch (status) {
  case SHIBRPC_OK:
    break;

  case SHIBRPC_UNKNOWN_ERROR:
    retval = "Unknown error: ";
    break;

  case SHIBRPC_IPADDR_MISMATCH:
    retval =
      "IP Address Mismatch: "
      "Your IP Address does not match the your authentication token.";
    break;

  case SHIBRPC_NO_SESSION:
    retval =
      "No Session: "
      "This server could not find a session for you.  This should not happen.<p>\n"
      "The only information about this error is:";
    break;

  case SHIBRPC_XML_EXCEPTION:
    retval = "Xerces XML Exception: ";
    break;

  case SHIBRPC_SAML_EXCEPTION:
    retval = "Unknown OpenSAML Exception: ";
    break;

  case SHIBRPC_INTERNAL_ERROR:
    retval = "Internal Error: ";
    break;

  case SHIBRPC_SAX_EXCEPTION:
    retval = "Xerces SAX Exception: ";
    break;

  case SHIBRPC_SESSION_EXPIRED:
    retval =
      "Session Expired: "
      "Your Shibboleth Session has expired.  Please log in again.";
    break;

  case SHIBRPC_AUTHSTATEMENT_MISSING:
    retval =
      "Authentication Statement Missing: "
      "The assertion of your Shibboleth identity was missing or incompatible "
      "with the policies of this site.";
    break;

  case SHIBRPC_IPADDR_MISSING:
    retval =
      "IP Address Missing: "
      "This site requires your Shibboleth to provide your IP Address in your "
      "identity assertion.";
    break;

  case SHIBRPC_RESPONSE_MISSING:
    retval =
      "SAML Response Missing: "
      "The assertion of your Shibboleth Identity was missing in the response "
      "or incompatible with the policies of this site.";
    break;

  case SHIBRPC_ASSERTION_MISSING:
    retval =
      "SAML Assertion Missing: "
      "Could not find the SSO assertion while processing your SAML Response.";
    break;

  case SHIBRPC_ASSERTION_REPLAYED:
    retval =
      "SAML Assertion Replayed: "
      "This SAML Response has already been seen.  Either you double-clicked "
      "while submitting the response or someone is trying to attack this server.";
    break;

  default:
    retval =
      "An unknown Shibboleth error occurred at this server.\n"
      "Contact the server adminstrator for more information.\n";
    break;
  }

  retval.append ("<p>\n");
  retval.append (error_msg);

  return retval;
}

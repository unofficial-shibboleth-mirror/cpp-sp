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

ShibTargetException::ShibTargetException(ShibRpcStatus code, const char* msg, const IEntityDescriptor* provider) : m_code(code)
{
    if (msg) m_msg=msg;
    if (provider) {
        auto_ptr_char id(provider->getId());
        m_providerId=id.get();
        Iterator<const IRoleDescriptor*> roles=provider->getRoleDescriptors();
        while (roles.hasNext()) {
            const IRoleDescriptor* role=roles.next();
            if (role->isValid()) {
                const char* temp=role->getErrorURL();
                if (temp) {
                    m_errorURL=temp;
                    break;
                }
            }
        }

        Iterator<const IContactPerson*> i=provider->getContactPersons();
        while (i.hasNext()) {
            const IContactPerson* c=i.next();
            if ((c->getType()==IContactPerson::technical || c->getType()==IContactPerson::support)) {
                const char* fname=c->getGivenName();
                const char* lname=c->getSurName();
                if (fname && lname)
                    m_contact=string(fname) + ' ' + lname;
                else if (fname)
                    m_contact=fname;
                else if (lname)
                    m_contact=lname;
                Iterator<string> emails=c->getEmailAddresses();
                if (emails.hasNext())
                    m_email=emails.next();
                return;
            }
        }
    }
}

ShibTargetException::ShibTargetException(ShibRpcStatus code, const char* msg, const IRoleDescriptor* role) : m_code(code)
{
    if (msg) m_msg=msg;
    if (role) {
        auto_ptr_char id(role->getEntityDescriptor()->getId());
        m_providerId=id.get();

        const char* temp=role->getErrorURL();
        if (temp)
            m_errorURL=temp;

        Iterator<const IContactPerson*> i=role->getContactPersons();
        while (i.hasNext()) {
            const IContactPerson* c=i.next();
            if ((c->getType()==IContactPerson::technical || c->getType()==IContactPerson::support)) {
                const char* fname=c->getGivenName();
                const char* lname=c->getSurName();
                if (fname && lname)
                    m_contact=string(fname) + ' ' + lname;
                else if (fname)
                    m_contact=fname;
                else if (lname)
                    m_contact=lname;
                Iterator<string> emails=c->getEmailAddresses();
                if (emails.hasNext())
                    m_email=emails.next();
                return;
            }
        }
    }
}

class shibtarget::RPCErrorPriv {
public:
  RPCErrorPriv(
    int stat=0,
    const char* msg=NULL,
    const char* provider=NULL,
    const char* url=NULL,
    const char* contact=NULL,
    const char* email=NULL
    );
  ~RPCErrorPriv();

  int status;
  string error_msg,m_provider,m_url,m_contact,m_email;
  SAMLException* except;
};

RPCErrorPriv::RPCErrorPriv(
    int stat, const char* msg, const char* provider, const char* url, const char* contact, const char* email
    ) : status(stat), except(NULL)
{
  log4cpp::Category& log = log4cpp::Category::getInstance("shibtarget.RPCErrorPriv");

  if (provider)
    m_provider=provider;
  if (url)
    m_url=url;
  if (contact)
    m_contact=contact;
  if (email)
    m_email=email;

  if (status == SHIBRPC_SAML_EXCEPTION) {
    istringstream estr(msg);
    try { 
      except = NULL;
      except = SAMLException::getInstance(estr);
    }
    catch (SAMLException& e) {
      log.error("Caught SAML Exception while building the SAMLException: %s", e.what());
      log.error("XML: %s", msg);
    }
    catch (XMLException& e) {
      log.error("Caught XML Exception building SAMLException: %s", e.getMessage());
      log.error("XML: %s", msg);
    }
    catch (...) {
      log.error("Caught exception building SAMLException!");
      log.error("XML: %s", msg);
    }
    if (dynamic_cast<ContentTypeException*>(except))
        error_msg =
          "We were unable to contact your identity provider and cannot grant "
          "access at this time. Please contact your provider's help desk or "
          "administrator so that the appropriate steps can be taken.  "
          "Be sure to describe what you're trying to access and useful "
          "context like the current time.";
    else if (except)
        error_msg = except->what();
    else if (msg)
        error_msg = msg;
  }
  else if (msg)
    error_msg = msg;
}

RPCErrorPriv::~RPCErrorPriv()
{
  if (except)
    delete except;
}

RPCError::RPCError() : m_priv(new RPCErrorPriv()) {}

RPCError::RPCError(ShibRpcError* e)
{
    if (!e || !e->status)
        m_priv=new RPCErrorPriv();
    m_priv=new RPCErrorPriv(
        e->status,
        e->ShibRpcError_u.e.error,
        e->ShibRpcError_u.e.provider,
        e->ShibRpcError_u.e.url,
        e->ShibRpcError_u.e.contact,
        e->ShibRpcError_u.e.email
        );
}

RPCError::RPCError(int s, const char* st) : m_priv(new RPCErrorPriv(s,st)) {}

RPCError::RPCError(ShibTargetException& exc)
    : m_priv(new RPCErrorPriv(exc.which(),exc.what(),exc.syswho(),exc.where(),exc.who(),exc.how())) {}

RPCError::~RPCError()
{
  delete m_priv;
}

bool RPCError::isError() { return (m_priv->status != 0); }

bool RPCError::isRetryable()
{
  switch (m_priv->status) {
  case SHIBRPC_NO_SESSION:
  case SHIBRPC_SESSION_EXPIRED:
    return true;

  case SHIBRPC_SAML_EXCEPTION:
    if (m_priv->except && dynamic_cast<RetryableProfileException*>(m_priv->except))
        return true;

    // FALLTHROUGH
    default:
        return false;
  }
}

const char* RPCError::getType()
{
  switch (m_priv->status) {
  case SHIBRPC_OK:                  return "No Error";
  case SHIBRPC_UNKNOWN_ERROR:       return "Unknown error";
  case SHIBRPC_INTERNAL_ERROR:      return "Internal Error";
  case SHIBRPC_XML_EXCEPTION:       return "Xerces XML Exception";
  case SHIBRPC_SAX_EXCEPTION:       return "Xerces SAX Exception";
  case SHIBRPC_SAML_EXCEPTION:      return m_priv->except->classname();

  case SHIBRPC_NO_SESSION:          return "No Session";
  case SHIBRPC_SESSION_EXPIRED:     return "Session Expired";
  case SHIBRPC_IPADDR_MISMATCH:     return "IP Address Mismatch";

  case SHIBRPC_IPADDR_MISSING:      return "IP Address Missing";
  case SHIBRPC_RESPONSE_MISSING:    return "SAML Response Missing";
  case SHIBRPC_ASSERTION_REPLAYED:  return "SAML Assertion Replayed";
  default:                          return "Unknown Shibboleth RPC error";
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
    if (i.hasNext() && XMLString::compareString(L(Responder),i.next().getLocalName()))
      return "An error occurred within the target system while processing your request";
    else
      return "An error occurred at your identity provider while processing your request";
  }
  else
    return "An error occurred while processing your request";
}

int RPCError::getCode() { return m_priv->status; }

const char* RPCError::getProviderId() { return m_priv->m_provider.c_str(); }

const char* RPCError::getErrorURL() { return m_priv->m_url.c_str(); }

const char* RPCError::getContactName() { return m_priv->m_contact.c_str(); }

const char* RPCError::getContactEmail() { return m_priv->m_email.c_str(); }

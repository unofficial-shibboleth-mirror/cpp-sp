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
 * Created by:    Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include "internal.h"

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <stdexcept>
#include <log4cpp/Category.hh>

using namespace std;
using namespace log4cpp;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

/* Parsing routines modified from NCSA source. */
static char *makeword(char *line, char stop)
{
    int x = 0,y;
    char *word = (char *) malloc(sizeof(char) * (strlen(line) + 1));

    for(x=0;((line[x]) && (line[x] != stop));x++)
        word[x] = line[x];

    word[x] = '\0';
    if(line[x])
        ++x;
    y=0;

    while(line[x])
      line[y++] = line[x++];
    line[y] = '\0';
    return word;
}

static char *fmakeword(char stop, unsigned int *cl, const char** ppch)
{
    int wsize;
    char *word;
    int ll;

    wsize = 1024;
    ll=0;
    word = (char *) malloc(sizeof(char) * (wsize + 1));

    while(1)
    {
        word[ll] = *((*ppch)++);
        if(ll==wsize-1)
        {
            word[ll+1] = '\0';
            wsize+=1024;
            word = (char *)realloc(word,sizeof(char)*(wsize+1));
        }
        --(*cl);
        if((word[ll] == stop) || word[ll] == EOF || (!(*cl)))
        {
            if(word[ll] != stop)
                ll++;
            word[ll] = '\0';
            return word;
        }
        ++ll;
    }
}

static char x2c(char *what)
{
    register char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));
    return(digit);
}

static void unescape_url(char *url)
{
    register int x,y;

    for(x=0,y=0;url[y];++x,++y)
    {
        if((url[x] = url[y]) == '%')
        {
            url[x] = x2c(&url[y+1]);
            y+=2;
        }
    }
    url[x] = '\0';
}

static void plustospace(char *str)
{
    register int x;

    for(x=0;str[x];x++)
        if(str[x] == '+') str[x] = ' ';
}

static inline char hexchar(unsigned short s)
{
    return (s<=9) ? ('0' + s) : ('A' + s - 10);
}

static string url_encode(const char* s)
{
    static char badchars[]="\"\\+<>#%{}|^~[]`;/?:@=&";

    string ret;
    for (; *s; s++) {
        if (strchr(badchars,*s) || *s<=0x1F || *s>=0x7F) {
            ret+='%';
        ret+=hexchar(*s >> 4);
        ret+=hexchar(*s & 0x0F);
        }
        else
            ret+=*s;
    }
    return ret;
}

namespace shibtarget {
    class CgiParse
    {
    public:
        CgiParse(const char* data, unsigned int len);
        ~CgiParse();
        const char* get_value(const char* name) const;
    
    private:
        map<string,char*> kvp_map;
    };
}

CgiParse::CgiParse(const char* data, unsigned int len)
{
    const char* pch = data;
    unsigned int cl = len;
        
    while (cl && pch) {
        char *name;
        char *value;
        value=fmakeword('&',&cl,&pch);
        plustospace(value);
        unescape_url(value);
        name=makeword(value,'=');
        kvp_map[name]=value;
        free(name);
    }
}

CgiParse::~CgiParse()
{
    for (map<string,char*>::iterator i=kvp_map.begin(); i!=kvp_map.end(); i++)
        free(i->second);
}

const char* CgiParse::get_value(const char* name) const
{
    map<string,char*>::const_iterator i=kvp_map.find(name);
    if (i==kvp_map.end())
        return NULL;
    return i->second;
}

SHIRE::~SHIRE()
{
    delete m_parser;
}

pair<const char*,const char*> SHIRE::getCookieNameProps() const
{
    static const char* defProps="; path=/";
    static const char* defName="_shibsession_";
    
    const IPropertySet* props=m_app->getPropertySet("Sessions");
    if (props) {
        pair<bool,const char*> p=props->getString("cookieProps");
        if (!p.first)
            p.second=defProps;
        if (!m_cookieName.empty())
            return pair<const char*,const char*>(m_cookieName.c_str(),p.second);
        pair<bool,const char*> p2=props->getString("cookieName");
        if (p2.first) {
            m_cookieName=p2.second;
            return pair<const char*,const char*>(p2.second,p.second);
        }
        m_cookieName=defName;
        m_cookieName+=m_app->getId();
        return pair<const char*,const char*>(m_cookieName.c_str(),p.second);
    }
    m_cookieName=defName;
    m_cookieName+=m_app->getId();
    return pair<const char*,const char*>(m_cookieName.c_str(),defProps);
}

const char* SHIRE::getShireURL(const char* resource) const
{
    if (!m_shireURL.empty())
        return m_shireURL.c_str();

    bool shire_ssl_only=false;
    const char* shire=NULL;
    const IPropertySet* props=m_app->getPropertySet("Sessions");
    if (props) {
        pair<bool,bool> p=props->getBool("shireSSL");
        if (p.first)
            shire_ssl_only=p.second;
        pair<bool,const char*> p2=props->getString("shireURL");
        if (p2.first)
            shire=p2.second;
    }
    
    // Should never happen...
    if (!shire)
        return NULL;

    // The "shireURL" property can be in one of three formats:
    //
    // 1) a full URI:       http://host/foo/bar
    // 2) a hostless URI:   http:///foo/bar
    // 3) a relative path:  /foo/bar
    //
    // #  Protocol  Host        Path
    // 1  shire     shire       shire
    // 2  shire     resource    shire
    // 3  resource  resource    shire
    //
    // note: if shire_ssl_only is true, make sure the protocol is https

    const char* path = NULL;

    // Decide whether to use the shire or the resource for the "protocol"
    const char* prot;
    if (*shire != '/') {
        prot = shire;
    }
    else {
        prot = resource;
        path = shire;
    }

    // break apart the "protocol" string into protocol, host, and "the rest"
    const char* colon=strchr(prot,':');
    colon += 3;
    const char* slash=strchr(colon,'/');
    if (!path)
        path = slash;

    // Compute the actual protocol and store in member.
    if (shire_ssl_only)
        m_shireURL.assign("https://");
    else
        m_shireURL.assign(prot, colon-prot);

    // create the "host" from either the colon/slash or from the target string
    // If prot == shire then we're in either #1 or #2, else #3.
    // If slash == colon then we're in #2.
    if (prot != shire || slash == colon) {
        colon = strchr(resource, ':');
        colon += 3;      // Get past the ://
        slash = strchr(colon, '/');
    }
    string host(colon, slash-colon);

    // Build the shire URL
    m_shireURL+=host + path;
    return m_shireURL.c_str();
}

const char* SHIRE::getAuthnRequest(const char* resource) const
{
    if (!m_authnRequest.empty())
        return m_authnRequest.c_str();
        
    char timebuf[16];
    sprintf(timebuf,"%u",time(NULL));
    
    const IPropertySet* props=m_app->getPropertySet("Sessions");
    if (props) {
        pair<bool,const char*> wayf=props->getString("wayfURL");
        if (wayf.first) {
            m_authnRequest=m_authnRequest + wayf.second + "?shire=" + url_encode(getShireURL(resource)) +
                "&target=" + url_encode(resource) + "&time=" + timebuf;
            pair<bool,bool> old=m_app->getBool("oldAuthnRequest");
            if (!old.first || !old.second) {
                wayf=m_app->getString("providerId");
                if (wayf.first)
                    m_authnRequest=m_authnRequest + "&providerId=" + url_encode(wayf.second);
            }
        }
    }
    return m_authnRequest.c_str();
}

const char* SHIRE::getLazyAuthnRequest(const char* query_string) const
{
    CgiParse parser(query_string,strlen(query_string));
    const char* target=parser.get_value("target");
    if (!target || !*target)
        return NULL;
    return getAuthnRequest(target);
}

pair<const char*,const char*> SHIRE::getFormSubmission(const char* post, unsigned int len) const
{
    m_parser = new CgiParse(post,len);
    return pair<const char*,const char*>(m_parser->get_value("SAMLResponse"),m_parser->get_value("TARGET"));
}

RPCError* SHIRE::sessionIsValid(const char* session_id, const char* ip) const
{
  saml::NDC ndc("sessionIsValid");
  Category& log = Category::getInstance("shibtarget.SHIRE");

  if (!session_id || !*session_id) {
    log.error ("No cookie value was provided");
    return new RPCError(SHIBRPC_NO_SESSION, "No cookie value was provided");
  }

  if (!ip || !*ip) {
    log.error ("Invalid IP Address");
    return new RPCError(SHIBRPC_IPADDR_MISSING, "Invalid IP Address");
  }

  log.info ("is session valid: %s", ip);
  log.debug ("session cookie: %s", session_id);

  shibrpc_session_is_valid_args_1 arg;

  arg.cookie.cookie = (char*)session_id;
  arg.cookie.client_addr = (char *)ip;
  arg.application_id = (char *)m_app->getId();
  
  // Get rest of input from the application Session properties.
  arg.lifetime = 3600;
  arg.timeout = 1800;
  arg.checkIPAddress = true;
  const IPropertySet* props=m_app->getPropertySet("Sessions");
  if (props) {
      pair<bool,unsigned int> p=props->getUnsignedInt("lifetime");
      if (p.first)
          arg.lifetime = p.second;
      p=props->getUnsignedInt("timeout");
      if (p.first)
          arg.timeout = p.second;
      pair<bool,bool> pcheck=props->getBool("checkAddress");
      if (pcheck.first)
          arg.checkIPAddress = pcheck.second;
  }
  
  shibrpc_session_is_valid_ret_1 ret;
  memset (&ret, 0, sizeof(ret));

  // Loop on the RPC in case we lost contact the first time through
  int retry = 1;
  CLIENT *clnt;
  RPC rpc;
  do {
    clnt = rpc->connect();
    if (shibrpc_session_is_valid_1(&arg, &ret, clnt) != RPC_SUCCESS) {
      // FAILED.  Release, disconnect, and try again...
      log.debug("RPC Failure: %p (%p): %s", this, clnt, clnt_spcreateerror(""));
      rpc->disconnect();
      if (retry)
          retry--;
      else {
        log.error("RPC Failure: %p (%p)", this, clnt);
        return new RPCError(-1, "RPC Failure");
      }
    }
    else {
      // SUCCESS.  Return to the pool.
      rpc.pool();
      retry = -1;
    }
  } while (retry>=0);

  log.debug("RPC completed with status %d, %p", ret.status.status, this);

  RPCError* retval;
  if (ret.status.status)
    retval = new RPCError(&ret.status);
  else
    retval = new RPCError();

  clnt_freeres (clnt, (xdrproc_t)xdr_shibrpc_session_is_valid_ret_1, (caddr_t)&ret);

  log.debug("returning");
  return retval;
}

RPCError* SHIRE::sessionCreate(const char* response, const char* ip, string& cookie) const
{
  saml::NDC ndc("sessionCreate");
  Category& log = Category::getInstance("shibtarget.SHIRE");

  if (!response || !*response) {
    log.error ("Empty SAML response content");
    return new RPCError(-1,  "Empty SAML response content");
  }

  if (!ip || !*ip) {
    log.error ("Invalid IP address");
    return new RPCError(-1, "Invalid IP address");
  }
  
  shibrpc_new_session_args_1 arg;
  arg.shire_location = (char*) m_shireURL.c_str();
  arg.application_id = (char*) m_app->getId();
  arg.saml_post = (char*)response;
  arg.client_addr = (char*)ip;
  arg.checkIPAddress = true;

  log.info ("create session for user at %s for application %s", ip, arg.application_id);

  const IPropertySet* props=m_app->getPropertySet("Sessions");
  if (props) {
      pair<bool,bool> pcheck=props->getBool("checkAddress");
      if (pcheck.first)
          arg.checkIPAddress = pcheck.second;
  }

  shibrpc_new_session_ret_1 ret;
  memset (&ret, 0, sizeof(ret));

  // Loop on the RPC in case we lost contact the first time through
  int retry = 1;
  CLIENT* clnt;
  RPC rpc;
  do {
    clnt = rpc->connect();
    if (shibrpc_new_session_1 (&arg, &ret, clnt) != RPC_SUCCESS) {
      // FAILED.  Release, disconnect, and retry
      log.debug("RPC Failure: %p (%p): %s", this, clnt, clnt_spcreateerror (""));
      rpc->disconnect();
      if (retry)
       retry--;
      else {
        log.error("RPC Failure: %p (%p)", this, clnt);
        return new RPCError(-1, "RPC Failure");
      }
    }
    else {
      // SUCCESS.  Pool and continue
      rpc.pool();
      retry = -1;
    }
  } while (retry>=0);

  log.debug("RPC completed with status %d (%p)", ret.status.status, this);

  RPCError* retval;
  if (ret.status.status)
    retval = new RPCError(&ret.status);
  else {
    log.debug ("new cookie: %s", ret.cookie);
    cookie = ret.cookie;
    retval = new RPCError();
  }

  clnt_freeres(clnt, (xdrproc_t)xdr_shibrpc_new_session_ret_1, (caddr_t)&ret);

  log.debug("returning");
  return retval;
}

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
 * shib-handlers.cpp -- profile handlers that plug into SP
 *
 * Scott Cantor
 * 5/17/2005
 */

#include "internal.h"

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <shib/shib-threads.h>
#include <log4cpp/Category.hh>
#include <xercesc/util/Base64.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>

#ifndef HAVE_STRCASECMP
# define strcasecmp stricmp
#endif

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;
using namespace log4cpp;

namespace {
  class CgiParse
  {
  public:
    CgiParse(const char* data, unsigned int len);
    ~CgiParse();
    const char* get_value(const char* name) const;
    
    static char x2c(char *what);
    static void url_decode(char *url);
    static string url_encode(const char* s);
  private:
    char * fmakeword(char stop, unsigned int *cl, const char** ppch);
    char * makeword(char *line, char stop);
    void plustospace(char *str);

    map<string,char*> kvp_map;
  };

    // Helper class for SAML 2.0 Common Domain Cookie operations
    class CommonDomainCookie
    {
    public:
        CommonDomainCookie(const char* cookie);
        ~CommonDomainCookie() {}
        saml::Iterator<std::string> get() {return m_list;}
        const char* set(const char* providerId);
        static const char CDCName[];
    private:
        std::string m_encoded;
        std::vector<std::string> m_list;
    };

  class SessionInitiator : virtual public IHandler
  {
  public:
    SessionInitiator(const DOMElement* e) {}
    ~SessionInitiator() {}
    pair<bool,void*> run(ShibTarget* st, const IPropertySet* handler, bool isHandler=true);
    pair<bool,void*> ShibAuthnRequest(
        ShibTarget* st,
        const IPropertySet* shire,
        const char* dest,
        const char* target,
        const char* providerId
        );
  };

  class SAML1Consumer : virtual public IHandler
  {
  public:
    SAML1Consumer(const DOMElement* e) {}
    ~SAML1Consumer() {}
    pair<bool,void*> run(ShibTarget* st, const IPropertySet* handler, bool isHandler=true);
  };

  class ShibLogout : virtual public IHandler
  {
  public:
    ShibLogout(const DOMElement* e) {}
    ~ShibLogout() {}
    pair<bool,void*> run(ShibTarget* st, const IPropertySet* handler, bool isHandler=true);
  };
}


IPlugIn* ShibSessionInitiatorFactory(const DOMElement* e)
{
    return new SessionInitiator(e);
}

IPlugIn* SAML1POSTFactory(const DOMElement* e)
{
    return new SAML1Consumer(e);
}

IPlugIn* SAML1ArtifactFactory(const DOMElement* e)
{
    return new SAML1Consumer(e);
}

IPlugIn* ShibLogoutFactory(const DOMElement* e)
{
    return new ShibLogout(e);
}

pair<bool,void*> SessionInitiator::run(ShibTarget* st, const IPropertySet* handler, bool isHandler)
{
    string dupresource;
    const char* resource=NULL;
    const IPropertySet* ACS=NULL;
    const IApplication* app=st->getApplication();
    
    if (isHandler) {
        /* 
         * Binding is CGI query string with:
         *  target      the resource to direct back to later
         *  acsIndex    optional index of an ACS to use on the way back in
         *  providerId  optional direct invocation of a specific IdP
         */
        string query=st->getArgs();
        CgiParse parser(query.c_str(),query.length());

        const char* option=parser.get_value("acsIndex");
        if (option)
            ACS=app->getAssertionConsumerServiceByIndex(atoi(option));
        option=parser.get_value("providerId");
        
        resource=parser.get_value("target");
        if (!resource || !*resource) {
            pair<bool,const char*> home=app->getString("homeURL");
            if (home.first)
                resource=home.second;
            else
                throw FatalProfileException("Session initiator requires a target parameter or a homeURL application property.");
        }
        else if (!option) {
            dupresource=resource;
            resource=dupresource.c_str();
        }
        
        if (option) {
            // Here we actually use metadata to invoke the SSO service directly.
            // The only currently understood binding is the Shibboleth profile.
            Metadata m(app->getMetadataProviders());
            const IEntityDescriptor* entity=m.lookup(option);
            if (!entity)
                throw MetadataException("Session initiator unable to locate metadata for provider ($1).", params(1,option));
            const IIDPSSODescriptor* role=entity->getIDPSSODescriptor(Constants::SHIB_NS);
            if (!role)
                throw MetadataException(
                    "Session initiator unable to locate a Shibboleth-aware identity provider role for provider ($1).", params(1,option)
                    );
            const IEndpointManager* SSO=role->getSingleSignOnServiceManager();
            const IEndpoint* ep=SSO->getEndpointByBinding(Constants::SHIB_AUTHNREQUEST_PROFILE_URI);
            if (!ep)
                throw MetadataException(
                    "Session initiator unable to locate compatible SSO service for provider ($1).", params(1,option)
                    );
            auto_ptr_char dest(ep->getLocation());
            return ShibAuthnRequest(
                st,ACS ? ACS : app->getDefaultAssertionConsumerService(),dest.get(),resource,app->getString("providerId").second
                );
        }
    }
    else {
        // We're running as a "virtual handler" from within the filter.
        // The target resource is the current one and everything else is defaulted.
        resource=st->getRequestURL();
    }
    
    if (!ACS) ACS=app->getDefaultAssertionConsumerService();
    
    // For now, we only support external session initiation via a wayfURL
    pair<bool,const char*> wayfURL=handler->getString("wayfURL");
    if (!wayfURL.first)
        throw ConfigurationException("Session initiator is missing wayfURL property.");

    pair<bool,const XMLCh*> wayfBinding=handler->getXMLString("wayfBinding");
    if (!wayfBinding.first || !XMLString::compareString(wayfBinding.second,Constants::SHIB_AUTHNREQUEST_PROFILE_URI))
        // Standard Shib 1.x
        return ShibAuthnRequest(st,ACS,wayfURL.second,resource,app->getString("providerId").second);
    else if (!XMLString::compareString(wayfBinding.second,Constants::SHIB_LEGACY_AUTHNREQUEST_PROFILE_URI))
        // Shib pre-1.2
        return ShibAuthnRequest(st,ACS,wayfURL.second,resource,NULL);
    else if (!strcmp(handler->getString("wayfBinding").second,"urn:mace:shibboleth:1.0:profiles:EAuth")) {
        // TODO: Finalize E-Auth profile URI
        pair<bool,bool> localRelayState=st->getConfig()->getPropertySet("Local")->getBool("localRelayState");
        if (!localRelayState.first || !localRelayState.second)
            throw ConfigurationException("E-Authn requests cannot include relay state, so localRelayState must be enabled.");

        // Here we store the state in a cookie.
        pair<string,const char*> shib_cookie=st->getCookieNameProps("_shibstate_");
        st->setCookie(shib_cookie.first,CgiParse::url_encode(resource) + shib_cookie.second);
        return make_pair(true, st->sendRedirect(wayfURL.second));
    }
   
    throw UnsupportedProfileException("Unsupported WAYF binding ($1).", params(1,handler->getString("wayfBinding").second));
}

// Handles Shib 1.x AuthnRequest profile.
pair<bool,void*> SessionInitiator::ShibAuthnRequest(
    ShibTarget* st,
    const IPropertySet* shire,
    const char* dest,
    const char* target,
    const char* providerId
    )
{
    // Compute the ACS URL. We add the ACS location to the handler baseURL.
    // Legacy configs will not have an ACS specified, so no suffix will be added.
    string ACSloc=st->getHandlerURL(target);
    if (shire) ACSloc+=shire->getString("Location").second;
    
    char timebuf[16];
    sprintf(timebuf,"%u",time(NULL));
    string req=string(dest) + "?shire=" + CgiParse::url_encode(ACSloc.c_str()) + "&time=" + timebuf;

    // How should the resource value be preserved?
    pair<bool,bool> localRelayState=st->getConfig()->getPropertySet("Local")->getBool("localRelayState");
    if (!localRelayState.first || !localRelayState.second) {
        // The old way, just send it along.
        req+="&target=" + CgiParse::url_encode(target);
    }
    else {
        // Here we store the state in a cookie and send a fixed
        // value to the IdP so we can recognize it on the way back.
        pair<string,const char*> shib_cookie=st->getCookieNameProps("_shibstate_");
        st->setCookie(shib_cookie.first,CgiParse::url_encode(target) + shib_cookie.second);
        req+="&target=cookie";
    }
    
    // Only omitted for 1.1 style requests.
    if (providerId)
        req+="&providerId=" + CgiParse::url_encode(providerId);

    return make_pair(true, st->sendRedirect(req));
}

pair<bool,void*> SAML1Consumer::run(ShibTarget* st, const IPropertySet* handler, bool isHandler)
{
    int profile=0;
    string input,cookie,target,providerId;
    const IApplication* app=st->getApplication();
    
    // Supports either version...
    pair<bool,unsigned int> version=handler->getUnsignedInt("MinorVersion","urn:oasis:names:tc:SAML:1.0:protocol");
    if (!version.first)
        version.second=1;

    pair<bool,const XMLCh*> binding=handler->getXMLString("Binding");
    if (!binding.first || !XMLString::compareString(binding.second,SAMLBrowserProfile::BROWSER_POST)) {
        if (strcasecmp(st->getRequestMethod(), "POST"))
            throw FatalProfileException(
                "SAML 1.x Browser/POST handler does not support HTTP method ($1).", params(1,st->getRequestMethod())
                );
        
        if (!st->getContentType() || strcasecmp(st->getContentType(),"application/x-www-form-urlencoded"))
            throw FatalProfileException(
                "Blocked invalid content-type ($1) submitted to SAML 1.x Browser/POST handler.", params(1,st->getContentType())
                );
        input=st->getPostData();
        profile|=(version.second==1 ? SAML11_POST : SAML10_POST);
    }
    else if (!XMLString::compareString(binding.second,SAMLBrowserProfile::BROWSER_ARTIFACT)) {
        if (strcasecmp(st->getRequestMethod(), "GET"))
            throw FatalProfileException(
                "SAML 1.x Browser/Artifact handler does not support HTTP method ($1).", params(1,st->getRequestMethod())
                );
        input=st->getArgs();
        profile|=(version.second==1 ? SAML11_ARTIFACT : SAML10_ARTIFACT);
    }
    
    if (input.empty())
        throw FatalProfileException("SAML 1.x Browser Profile handler received no data from browser.");
    
    string hURL=st->getHandlerURL(st->getRequestURL());
    pair<bool,const char*> loc=handler->getString("Location");
    string recipient=loc.first ? hURL + loc.second : hURL;
    st->getConfig()->getListener()->sessionNew(
        app,
        profile,
        recipient.c_str(),
        input.c_str(),
        st->getRemoteAddr(),
        target,
        cookie,
        providerId
        );

    st->log(ShibTarget::LogLevelDebug, string("profile processing succeeded, new session created (") + cookie + ")");

    if (target=="default") {
        pair<bool,const char*> homeURL=app->getString("homeURL");
        target=homeURL.first ? homeURL.second : "/";
    }
    else if (target=="cookie") {
        // Pull the target value from the "relay state" cookie.
        pair<string,const char*> relay_cookie = st->getCookieNameProps("_shibstate_");
        const char* relay_state = st->getCookie(relay_cookie.first);
        if (!relay_state || !*relay_state) {
            // No apparent relay state value to use, so fall back on the default.
            pair<bool,const char*> homeURL=app->getString("homeURL");
            target=homeURL.first ? homeURL.second : "/";
        }
        else {
            char* rscopy=strdup(relay_state);
            CgiParse::url_decode(rscopy);
            target=rscopy;
            free(rscopy);
        }
    }

    // We've got a good session, set the session cookie.
    pair<string,const char*> shib_cookie=st->getCookieNameProps("_shibsession_");
    st->setCookie(shib_cookie.first, cookie + shib_cookie.second);

    const IPropertySet* sessionProps=app->getPropertySet("Sessions");
    pair<bool,bool> idpHistory=sessionProps->getBool("idpHistory");
    if (!idpHistory.first || idpHistory.second) {
        // Set an IdP history cookie locally (essentially just a CDC).
        CommonDomainCookie cdc(st->getCookie(CommonDomainCookie::CDCName));

        // Either leave in memory or set an expiration.
        pair<bool,unsigned int> days=sessionProps->getUnsignedInt("idpHistoryDays");
            if (!days.first || days.second==0)
                st->setCookie(CommonDomainCookie::CDCName,string(cdc.set(providerId.c_str())) + shib_cookie.second);
            else {
                time_t now=time(NULL) + (days.second * 24 * 60 * 60);
#ifdef HAVE_GMTIME_R
                struct tm res;
                struct tm* ptime=gmtime_r(&now,&res);
#else
                struct tm* ptime=gmtime(&now);
#endif
                char timebuf[64];
                strftime(timebuf,64,"%a, %d %b %Y %H:%M:%S GMT",ptime);
                st->setCookie(
                    CommonDomainCookie::CDCName,
                    string(cdc.set(providerId.c_str())) + shib_cookie.second + "; expires=" + timebuf
                    );
        }
    }

    // Now redirect to the target.
    return make_pair(true, st->sendRedirect(target));
}

pair<bool,void*> ShibLogout::run(ShibTarget* st, const IPropertySet* handler, bool isHandler)
{
    // Recover the session key.
    pair<string,const char*> shib_cookie = st->getCookieNameProps("_shibsession_");
    const char* session_id = st->getCookie(shib_cookie.first);
    
    // Logout is best effort.
    if (session_id && *session_id) {
        try {
            st->getConfig()->getListener()->sessionEnd(st->getApplication(),session_id);
        }
        catch (SAMLException& e) {
            st->log(ShibTarget::LogLevelError, string("logout processing failed with exception: ") + e.what());
        }
#ifndef _DEBUG
        catch (...) {
            st->log(ShibTarget::LogLevelError, "logout processing failed with unknown exception");
        }
#endif
        st->setCookie(shib_cookie.first,"");
    }
    
    string query=st->getArgs();
    CgiParse parser(query.c_str(),query.length());

    const char* ret=parser.get_value("return");
    if (!ret)
        ret=handler->getString("ResponseLocation").second;
    if (!ret)
        ret=st->getApplication()->getString("homeURL").second;
    if (!ret)
        ret="/";
    return make_pair(true, st->sendRedirect(ret));
}

/*************************************************************************
 * CGI Parser implementation
 */

CgiParse::CgiParse(const char* data, unsigned int len)
{
    const char* pch = data;
    unsigned int cl = len;
        
    while (cl && pch) {
        char *name;
        char *value;
        value=fmakeword('&',&cl,&pch);
        plustospace(value);
        url_decode(value);
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

const char*
CgiParse::get_value(const char* name) const
{
    map<string,char*>::const_iterator i=kvp_map.find(name);
    if (i==kvp_map.end())
        return NULL;
    return i->second;
}

/* Parsing routines modified from NCSA source. */
char *
CgiParse::makeword(char *line, char stop)
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

char *
CgiParse::fmakeword(char stop, unsigned int *cl, const char** ppch)
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

void
CgiParse::plustospace(char *str)
{
    register int x;

    for(x=0;str[x];x++)
        if(str[x] == '+') str[x] = ' ';
}

char
CgiParse::x2c(char *what)
{
    register char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A')+10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A')+10 : (what[1] - '0'));
    return(digit);
}

void
CgiParse::url_decode(char *url)
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

static inline char hexchar(unsigned short s)
{
    return (s<=9) ? ('0' + s) : ('A' + s - 10);
}

string CgiParse::url_encode(const char* s)
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

// CDC implementation

const char CommonDomainCookie::CDCName[] = "_saml_idp";

CommonDomainCookie::CommonDomainCookie(const char* cookie)
{
    if (!cookie)
        return;

    Category& log=Category::getInstance(SHIBT_LOGCAT".CommonDomainCookie");

    // Copy it so we can URL-decode it.
    char* b64=strdup(cookie);
    CgiParse::url_decode(b64);

    // Chop it up and save off elements.
    vector<string> templist;
    char* ptr=b64;
    while (*ptr) {
        while (*ptr && isspace(*ptr)) ptr++;
        char* end=ptr;
        while (*end && !isspace(*end)) end++;
        templist.push_back(string(ptr,end-ptr));
        ptr=end;
    }
    free(b64);

    // Now Base64 decode the list.
    for (vector<string>::iterator i=templist.begin(); i!=templist.end(); i++) {
        unsigned int len;
        XMLByte* decoded=Base64::decode(reinterpret_cast<const XMLByte*>(i->c_str()),&len);
        if (decoded && *decoded) {
            m_list.push_back(reinterpret_cast<char*>(decoded));
            XMLString::release(&decoded);
        }
        else
            log.warn("cookie element does not appear to be base64-encoded");
    }
}

const char* CommonDomainCookie::set(const char* providerId)
{
    // First scan the list for this IdP.
    for (vector<string>::iterator i=m_list.begin(); i!=m_list.end(); i++) {
        if (*i == providerId) {
            m_list.erase(i);
            break;
        }
    }
    
    // Append it to the end.
    m_list.push_back(providerId);
    
    // Now rebuild the delimited list.
    string delimited;
    for (vector<string>::const_iterator j=m_list.begin(); j!=m_list.end(); j++) {
        if (!delimited.empty()) delimited += ' ';
        
        unsigned int len;
        XMLByte* b64=Base64::encode(reinterpret_cast<const XMLByte*>(j->c_str()),j->length(),&len);
        XMLByte *pos, *pos2;
        for (pos=b64, pos2=b64; *pos2; pos2++)
            if (isgraph(*pos2))
                *pos++=*pos2;
        *pos=0;
        
        delimited += reinterpret_cast<char*>(b64);
        XMLString::release(&b64);
    }
    
    m_encoded=CgiParse::url_encode(delimited.c_str());
    return m_encoded.c_str();
}

/*
 *  Copyright 2001-2005 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* adfs.cpp - bootstraps the ADFS extension library

   Scott Cantor
   10/10/05
*/

#ifdef WIN32
# define ADFS_EXPORTS __declspec(dllexport)
#else
# define ADFS_EXPORTS
#endif

#include "internal.h"

#include <xercesc/util/Base64.hpp>


using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;
using namespace adfs;
using namespace adfs::logging;


// Plugin Factories
PlugManager::Factory ADFSListenerFactory;
PlugManager::Factory ADFSSessionInitiatorFactory;
PlugManager::Factory ADFSHandlerFactory;

IListener* adfs::g_MemoryListener = NULL;

extern "C" int ADFS_EXPORTS saml_extension_init(void*)
{
    SAMLConfig& conf=SAMLConfig::getConfig();

    if (ShibTargetConfig::getConfig().isEnabled(ShibTargetConfig::Caching)) {
        // Build an internal "listener" to handle the work.
        IPlugIn* plugin=conf.getPlugMgr().newPlugin(shibtarget::XML::MemoryListenerType,NULL);
        g_MemoryListener=dynamic_cast<IListener*>(plugin);
        if (!g_MemoryListener) {
            delete plugin;
            fprintf(stderr, "Basic MemoryListener plugin failed to load");
            return -1;
        }
    }
    
    // Register extension schema.
    saml::XML::registerSchema(adfs::XML::WSTRUST_NS,adfs::XML::WSTRUST_SCHEMA_ID);

    // Register plugin factories (some override existing Shib functionality).
    conf.getPlugMgr().regFactory(shibtarget::XML::MemoryListenerType,&ADFSListenerFactory);

    auto_ptr_char temp1(Constants::SHIB_SESSIONINIT_PROFILE_URI);
    conf.getPlugMgr().regFactory(temp1.get(),&ADFSSessionInitiatorFactory);

    auto_ptr_char temp2(adfs::XML::WSFED_NS);
    conf.getPlugMgr().regFactory(temp2.get(),&ADFSHandlerFactory);

    return 0;
}

extern "C" void ADFS_EXPORTS saml_extension_term()
{
    // Unregister metadata factories
    SAMLConfig& conf=SAMLConfig::getConfig();
    conf.getPlugMgr().unregFactory(shibtarget::XML::MemoryListenerType);
    
    auto_ptr_char temp1(Constants::SHIB_SESSIONINIT_PROFILE_URI);
    conf.getPlugMgr().unregFactory(temp1.get());
    
    auto_ptr_char temp2(adfs::XML::WSFED_NS);
    conf.getPlugMgr().unregFactory(temp2.get());
    
    delete g_MemoryListener;
    g_MemoryListener=NULL;
}

// For now, we'll just put the meat of the profile here.

SAMLAuthenticationStatement* adfs::checkAssertionProfile(const SAMLAssertion* a)
{
    // Is it signed?
    if (!a->isSigned())
        throw FatalProfileException("rejected unsigned ADFS assertion");
    
    // Is it valid?
    time_t now=time(NULL);
    SAMLConfig& config=SAMLConfig::getConfig();
    if (a->getIssueInstant()->getEpoch() < now-(2*config.clock_skew_secs))
        throw ExpiredAssertionException("rejected expired ADFS assertion");

    const SAMLDateTime* notBefore=a->getNotBefore();
    const SAMLDateTime* notOnOrAfter=a->getNotOnOrAfter();
    if (!notBefore || !notOnOrAfter)
        throw ExpiredAssertionException("rejected ADFS assertion without time conditions");
    if (now+config.clock_skew_secs < notBefore->getEpoch())
        throw ExpiredAssertionException("rejected ADFS assertion that is not yet valid");
    if (notOnOrAfter->getEpoch() <= now-config.clock_skew_secs)
        throw ExpiredAssertionException("rejected expired ADFS assertion");

    // Look for an authentication statement.
    SAMLAuthenticationStatement* as=NULL;
    for (Iterator<SAMLStatement*> statements=a->getStatements(); !as && statements.hasNext();)
        as=dynamic_cast<SAMLAuthenticationStatement*>(statements.next());
    if (!as)
        throw FatalProfileException("rejecting ADFS assertion without authentication statement");

    return as;
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
        if((url[x] = url[y]) == '%' && isxdigit(url[y+1]) && isxdigit(url[y+2]))
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
    static char badchars[]="\"\\+<>#%{}|^~[]`,;/?:@=&";

    string ret;
    for (; *s; s++) {
        if (strchr(badchars,*s) || *s<=0x20 || *s>=0x7F) {
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

    Category& log=Category::getInstance(ADFS_LOGCAT".CommonDomainCookie");

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

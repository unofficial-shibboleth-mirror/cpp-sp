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
 * shib-mlp.cpp -- The ShibTarget Markup Language processor
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include "internal.h"

#include <sstream>
#include <ctype.h>
#include <xercesc/util/XercesDefs.hpp>
#include <log4cpp/Category.hh>

using namespace std;
using namespace log4cpp;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

class shibtarget::ShibMLPPriv {
public:
  ShibMLPPriv();
  ~ShibMLPPriv() {}
  log4cpp::Category *log;
};  

ShibMLPPriv::ShibMLPPriv() : log(&(log4cpp::Category::getInstance("shibtarget.ShibMLP"))) {}

static void trimspace (string& s)
{
  int end = s.size() - 1, start = 0;

  // Trim stuff on right.
  while (end > 0 && !isgraph(s[end])) end--;

  // Trim stuff on left.
  while (start < end && !isgraph(s[start])) start++;

  // Modify the string.
  s = s.substr(start, end - start + 1);
}

ShibMLP::ShibMLP()
{
  m_priv = new ShibMLPPriv ();
}

ShibMLP::~ShibMLP ()
{
  delete m_priv;
}

const char* ShibMLP::run(const string& is, const IPropertySet* props, std::string* output)
{
  // Create a timestamp
  time_t now = time(NULL);
  insert("now", ctime(&now));

  if (!output)
    output=&m_generated;
  const char* line = is.c_str();
  const char* lastpos = line;
  const char* thispos;

  m_priv->log->info("Processing string");

  //
  // Search for SHIBMLP tags.  These are of the form:
  //	<shibmlp key/>
  //    <shibmlpif key> stuff </shibmlpif>
  //    <shibmlpifnot key> stuff </shibmlpifnot>
  // Note that there MUST be white-space after "<shibmlp" but
  // there does not need to be white space between the key and
  // the close-tag.
  //
  while ((thispos = strchr(lastpos, '<')) != NULL) {
    // save the string up to this token
    *output += is.substr(lastpos-line, thispos-lastpos);

    // Make sure this token matches our tokens.
#ifdef HAVE_STRCASECMP
    if (!strncasecmp(thispos, "<shibmlp ", 9))
#else
    if (!strnicmp(thispos, "<shibmlp ", 9))
#endif
    {
        // Save this position off.
        lastpos = thispos + 9;  // strlen("<shibmlp ")
    
        // search for the end-tag
        if ((thispos = strstr(lastpos, "/>")) != NULL) {
            string key = is.substr(lastpos-line, thispos-lastpos);
            trimspace(key);
    
            map<string,string>::const_iterator i=m_map.find(key);
            if (i != m_map.end()) {
                *output += i->second;
            }
            else {
                pair<bool,const char*> p=props ? props->getString(key.c_str()) : pair<bool,const char*>(false,NULL);
                if (p.first) {
                    *output += p.second;
                }
                else {
                    static const char* s1 = "<!-- Unknown SHIBMLP key: ";
                    static const char* s2 = "/>";
                    *output += s1;
                    *output += key + s2;
                }
            }
            lastpos = thispos + 2; // strlen("/>")
        }
    }
#ifdef HAVE_STRCASECMP
    else if (!strncasecmp(thispos, "<shibmlpif ", 11))
#else
    else if (!strnicmp(thispos, "<shibmlpif ", 11))
#endif
    {
        // Save this position off.
        lastpos = thispos + 11;  // strlen("<shibmlpif ")

        // search for the end of this tag
        if ((thispos = strchr(lastpos, '>')) != NULL) {
            string key = is.substr(lastpos-line, thispos-lastpos);
            trimspace(key);
            bool eval=false;
            map<string,string>::const_iterator i=m_map.find(key);
            if (i != m_map.end() && !i->second.empty()) {
                eval=true;
            }
            else {
                pair<bool,const char*> p=props ? props->getString(key.c_str()) : pair<bool,const char*>(false,NULL);
                if (p.first) {
                    eval=true;
                }
            }
            lastpos = thispos + 1; // strlen(">")
            
            // Search for the closing tag.
            const char* frontpos=lastpos;
            while ((thispos = strstr(lastpos, "</")) != NULL) {
#ifdef HAVE_STRCASECMP
                if (!strncasecmp(thispos, "</shibmlpif>", 12))
#else
                if (!strnicmp(thispos, "</shibmlpif>", 12))
#endif
                {
                    // We found our terminator. Process the string in between.
                    string segment;
                    run(is.substr(frontpos-line, thispos-frontpos),props,&segment);
                    if (eval)
                        *output += segment;
                    lastpos = thispos + 12; // strlen("</shibmlpif>")
                    break;
                }
                else {
                    // Skip it.
                    lastpos = thispos + 2;
                }
            }
        }
    }
#ifdef HAVE_STRCASECMP
    else if (!strncasecmp(thispos, "<shibmlpifnot ", 14))
#else
    else if (!strnicmp(thispos, "<shibmlpifnot ", 14))
#endif
    {
        // Save this position off.
        lastpos = thispos + 14;  // strlen("<shibmlpifnot ")

        // search for the end of this tag
        if ((thispos = strchr(lastpos, '>')) != NULL) {
            string key = is.substr(lastpos-line, thispos-lastpos);
            trimspace(key);
            bool eval=false;
            map<string,string>::const_iterator i=m_map.find(key);
            if (i != m_map.end() && !i->second.empty()) {
                eval=true;
            }
            else {
                pair<bool,const char*> p=props ? props->getString(key.c_str()) : pair<bool,const char*>(false,NULL);
                if (p.first) {
                    eval=true;
                }
            }
            lastpos = thispos + 1; // strlen(">")
            
            // Search for the closing tag.
            const char* frontpos=lastpos;
            while ((thispos = strstr(lastpos, "</")) != NULL) {
#ifdef HAVE_STRCASECMP
                if (!strncasecmp(thispos, "</shibmlpifnot>", 15))
#else
                if (!strnicmp(thispos, "</shibmlpifnot>", 15))
#endif
                {
                    // We found our terminator. Process the string in between.
                    string segment;
                    run(is.substr(frontpos-line, thispos-frontpos),props,&segment);
                    if (!eval)
                        *output += segment;
                    lastpos = thispos + 15; // strlen("</shibmlpifnot>")
                    break;
                }
                else {
                    // Skip it.
                    lastpos = thispos + 2;
                }
            }
        }
    }
    else {
      // Skip it.
      *output += "<";
      lastpos = thispos + 1;
    }
  }
  *output += is.substr(lastpos-line);

  return output->c_str();
}

const char* ShibMLP::run(istream& is, const IPropertySet* props, std::string* output)
{
  static string eol = "\r\n";
  string str, line;

  m_priv->log->info("processing stream");

  while (getline(is, line))
    str += line + eol;

  return run(str,props,output);
}

void ShibMLP::insert(SAMLException& e)
{
    insert("errorType", e.classname());
    if (typeid(e)==typeid(ContentTypeException))
        insert("errorText", "A problem was detected with your identity provider's software configuration.");
    else
        insert("errorText", e.getMessage() ? e.getMessage() : "No Message");
    if (e.getProperty("errorURL"))
        insert("originErrorURL", e.getProperty("errorURL"));
    if (e.getProperty("contactName"))
        insert("originContactName", e.getProperty("contactName"));
    if (e.getProperty("contactEmail"))
        insert("originContactEmail", e.getProperty("contactEmail"));
}

void ShibMLP::insert (const std::string& key, const std::string& value)
{
  m_priv->log->debug("inserting %s -> %s", key.c_str(), value.c_str());
  m_map[key] = value;
}

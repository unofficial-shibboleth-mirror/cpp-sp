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

  static void html_encode(string& os, const char* start);
};  


void ShibMLPPriv::html_encode(string& os, const char* start)
{
    while (start && *start) {
        switch (*start) {
            case '<':   os += "&lt;";       break;
            case '>':   os += "&gt;";       break;
            case '"':   os += "&quot;";     break;
            case '#':   os += "&#35;";      break;
            case '%':   os += "&#37;";      break;
            case '&':   os += "&#38;";      break;
            case '\'':  os += "&#39;";      break;
            case '(':   os += "&#40;";      break;
            case ')':   os += "&#41;";      break;
            case ':':   os += "&#58;";      break;
            case '[':   os += "&#91;";      break;
            case '\\':  os += "&#92;";      break;
            case ']':   os += "&#93;";      break;
            case '`':   os += "&#96;";      break;
            case '{':   os += "&#123;";     break;
            case '}':   os += "&#125;";     break;
            default:    os += *start;
        }
        start++;
    }
}

ShibMLPPriv::ShibMLPPriv() : log(&(log4cpp::Category::getInstance("shibtarget.ShibMLP"))) {}

static void trimspace (string& s)
{
  size_t end = s.size() - 1, start = 0;

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

  m_priv->log->debug("Processing string");

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
    if (!_strnicmp(thispos, "<shibmlp ", 9))
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
                m_priv->html_encode(*output,i->second.c_str());
            }
            else {
                pair<bool,const char*> p=props ? props->getString(key.c_str()) : pair<bool,const char*>(false,NULL);
                if (p.first) {
                    m_priv->html_encode(*output,p.second);
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
    else if (!_strnicmp(thispos, "<shibmlpif ", 11))
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
                if (!_strnicmp(thispos, "</shibmlpif>", 12))
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
    else if (!_strnicmp(thispos, "<shibmlpifnot ", 14))
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
                if (!_strnicmp(thispos, "</shibmlpifnot>", 15))
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

  m_priv->log->debug("processing stream");

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
    const char* email=e.getProperty("contactEmail");
    if (email) {
        if (!strncmp(email,"mailto:",7) && strlen(email)>7)
            insert("originContactEmail", email+7);
        else
            insert("originContactEmail", email);
    }
}

void ShibMLP::insert (const std::string& key, const std::string& value)
{
  m_priv->log->debug("inserting %s -> %s", key.c_str(), value.c_str());
  m_map[key] = value;
}

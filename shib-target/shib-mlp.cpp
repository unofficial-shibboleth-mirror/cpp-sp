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

  // Create a timestamp
  time_t now = time(NULL);
  insert("now", ctime(&now));
}

ShibMLP::~ShibMLP ()
{
  delete m_priv;
}

const char* ShibMLP::run(const string& is, const IPropertySet* props)
{
  const char* line = is.c_str();
  const char* lastpos = line;
  const char* thispos;

  m_generated.erase();
  m_priv->log->info("Processing string");

  //
  // Search for SHIBMLP tags.  These are of the form:
  //	<shibmlp key />
  // Note that there MUST be white-space after "<shibmlp" but
  // there does not need to be white space between the key and
  // the close-tag.
  //
  while ((thispos = strstr(lastpos, "<")) != NULL) {
    // save the string up to this token
    m_generated += is.substr(lastpos-line, thispos-lastpos);

    // Make sure this token matches our token.
    if (strnicmp (thispos, "<shibmlp ", 9)) {
      m_generated += "<";
      lastpos = thispos + 1;
      continue;
    }

    // Save this position off.
    lastpos = thispos + 9;	// strlen("<shibmlp ")

    // search for the end-tag
    if ((thispos = strstr(lastpos, "/>")) != NULL) {
      string key = is.substr(lastpos-line, thispos-lastpos);
      trimspace(key);

      m_priv->log->debug("found key: \"%s\"", key.c_str());

      map<string,string>::const_iterator i=m_map.find(key);
      if (i != m_map.end()) {
        m_generated += i->second;
        m_priv->log->debug("key maps to \"%s\"", i->second.c_str());
      }
      else {
        pair<bool,const char*> p=props ? props->getString(key.c_str()) : pair<bool,const char*>(false,NULL);
        if (p.first) {
            m_generated += p.second;
            m_priv->log->debug("property maps to \"%s\"", p.second);
        }
        else {
            static string s1 = "<!-- Unknown SHIBMLP key: ";
            static string s2 = "/>";
            m_generated += s1 + key + s2;
            m_priv->log->debug("key unknown");
        }
      }

      lastpos = thispos + 2;	// strlen("/>")
    }
  }
  m_generated += is.substr(lastpos-line);

  return m_generated.c_str();
}

const char* ShibMLP::run(istream& is, const IPropertySet* props)
{
  static string eol = "\r\n";
  string str, line;

  m_priv->log->info("processing stream");

  while (getline(is, line))
    str += line + eol;

  return run(str,props);
}

void ShibMLP::insert (RPCError& e)
{
    insert ("errorType", e.getType() ? e.getType() : "Unknown Type");
    insert ("errorText", e.getText() ? e.getText() : "No Message");
    insert ("errorDesc", e.getDesc() ? e.getDesc() : "No Description");
    insert ("originErrorURL", e.getErrorURL() ? e.getErrorURL() : "No Error URL");
    insert ("originContactName", e.getContactName() ? e.getContactName() : "No Contact Name");
    insert ("originContactEmail", e.getContactEmail() ? e.getContactEmail() : "No Contact Email");
}

void ShibMLP::insert (const std::string& key, const std::string& value)
{
  m_priv->log->debug("inserting %s -> %s", key.c_str(), value.c_str());
  m_map[key] = value;
}

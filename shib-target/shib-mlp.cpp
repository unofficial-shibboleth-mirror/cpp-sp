/*
 * shib-mlp.cpp -- The ShibTarget Markup Language processor
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include "shib-target.h"
#include <sstream>
#include <ctype.h>
#include <xercesc/util/XercesDefs.hpp>

#include <log4cpp/Category.hh>

using namespace std;
using namespace shibtarget;
using namespace saml;

class shibtarget::ShibMLPPriv {
public:
  ShibMLPPriv();
  ~ShibMLPPriv() {}
  log4cpp::Category *log;
};  

ShibMLPPriv::ShibMLPPriv()
{
  string ctx = "shibtarget.ShibMLP";
  log = &(log4cpp::Category::getInstance(ctx));
}


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

ShibMLP::ShibMLP ()
{
  m_priv = new ShibMLPPriv ();
}

ShibMLP::~ShibMLP ()
{
  delete m_priv;
}

string ShibMLP::run (const string& is) const
{
  string res;

  const char* line = is.c_str();
  const char* lastpos = line;
  const char* thispos;

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
    res += is.substr(lastpos-line, thispos-lastpos);

    // Make sure this token matches our token.
    if (strnicmp (thispos, "<shibmlp ", 9)) {
      res += "<";
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
      if (i == m_map.end()) {
	static string s1 = "<!-- Unknown SHIBMLP key: ";
	static string s2 = "/>";
	res += s1 + key + s2;
	m_priv->log->debug("key unknown");
      } else {
	res += i->second;
	m_priv->log->debug("key maps to \"%s\"", i->second.c_str());
      }

      lastpos = thispos + 2;	// strlen("/>")
    }
  }
  res += is.substr(lastpos-line);

  return res;
}

string ShibMLP::run (istream& is) const
{
  static string eol = "\r\n";
  string str, line;

  m_priv->log->info("processing stream");

  while (getline(is, line))
    str += line + eol;

  return run(str);
}

void ShibMLP::insert (RPCError& e)
{
  insert ("errorType", e.getType());
  insert ("errorText", e.getText());
  insert ("errorDesc", e.getDesc());
}

/*
 * shib-ini.h -- INI file handling
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include "shib-target.h"
#include <sstream>
#include <iostream>
#include <fstream>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <log4cpp/Category.hh>

using namespace std;
using namespace shibtarget;

class HeaderIterator : public shibtarget::ShibINI::Iterator {
public:
  HeaderIterator (ShibINIPriv* ini);
  ~HeaderIterator () { }

  const string* begin();
  const string* next();
private:
  ShibINIPriv* ini;
  map<string, map<string,string> >::const_iterator iter;
  bool valid;
};

class TagIterator : public ShibINI::Iterator {
public:
  TagIterator (ShibINIPriv* ini, const string& header);
  ~TagIterator () { }

  const string* begin();
  const string* next();
private:
  ShibINIPriv* ini;
  const string& header;
  map<string,string>::const_iterator iter;
  bool valid;
};

class shibtarget::ShibINIPriv {
public:
  ShibINIPriv();
  ~ShibINIPriv() { }
  log4cpp::Category *log;

  map<string, map<string, string> > table;
  string file;
  bool cs;

  unsigned long	modtime;
};

ShibINIPriv::ShibINIPriv()
{
  string ctx = "shibtarget.ShibINI";
  log = &(log4cpp::Category::getInstance(ctx));
}

static void trimline (string& s)
{
  int end = s.size() - 1, start = 0;

  // Trim stuff on right.
  while (end > 0 && !isgraph(s[end])) end--;

  // Trim stuff on left.
  while (start < end && !isgraph(s[start])) start++;

  // Modify the string.
  s = s.substr(start, end - start + 1);
}

static void to_lowercase (string& s)
{
  for (int i = 0, sz = s.size(); i < sz; i++)
    s[i] = tolower(s[i]);
}

ShibINI::~ShibINI() {
  delete m_priv;
}

void ShibINI::init (string& f, bool case_sensitive)
{
  m_priv = new ShibINIPriv();
  m_priv->file = f;
  m_priv->cs = case_sensitive;
  m_priv->log->info ("initializing INI file: %s (sensitive=%s)", f.c_str(),
		     (case_sensitive ? "true" : "false"));
  refresh();
}

void ShibINI::refresh(void)
{
  saml::NDC ndc("refresh");

  // check if we need to refresh
#ifdef _WIN32
  struct _stat stat_buf;
  if (_stat (m_priv->file.c_str(), &stat_buf) < 0)
#else
  struct stat stat_buf;
  if (stat (m_priv->file.c_str(), &stat_buf) < 0)
#endif
    m_priv->log->error("stat failed: %s", m_priv->file.c_str());

  if (m_priv->modtime == stat_buf.st_mtime)
    return;

  m_priv->modtime = stat_buf.st_mtime;

  // clear the existing maps
  m_priv->table.clear();

  m_priv->log->info("reading %s", m_priv->file.c_str());
  
  // read the file
  try
  {
    ifstream infile (m_priv->file.c_str());
    if (!infile) {
      m_priv->log->warn("cannot open file: %s", m_priv->file.c_str());
      return;
    }

    const int MAXLEN = 1024;
    char linebuffer[MAXLEN];
    string current_header;
    bool have_header = false;

    while (infile) {
      infile.getline (linebuffer, MAXLEN);
      string line (linebuffer);

      if (line[0] == '#') continue;

      trimline (line);
      if (line.size() <= 1) continue;

      if (line[0] == '[') {
	// this is a header

	m_priv->log->debug("Found what appears to be a header line");

	have_header = false;

	// find the end of the header
	int endpos = line.find (']');
	if (endpos == line.npos) {
	  m_priv->log->debug("Weird: no end found.. punting");
	  continue; // HUH?  No end?
	}

	// found it
	current_header = line.substr (1, endpos-1);
	trimline (current_header);

	if (!m_priv->cs) to_lowercase (current_header);

	m_priv->table[current_header] = map<string,string>();
	have_header = true;
	m_priv->log->debug("current header: \"%s\"", current_header.c_str());

      } else if (have_header) {
	// this is a tag

	m_priv->log->debug("Found what appears to be a tag line");

	string tag, setting;
	int mid = line.find ('=');

	if (mid == line.npos) {
	  m_priv->log->debug("Weird: no '=' found.. punting");
	  continue; // Can't find the value's setting
	}

	tag = line.substr (0,mid);
	setting = line.substr (mid+1, line.size()-mid);

	trimline (tag);
	trimline (setting);

	if (!m_priv->cs) to_lowercase (tag);

	// If it already exists, log an error and do not save it
	if (exists (current_header, tag))
	  m_priv->log->error("Duplicate tag found in section %s: \"%s\"",
			     current_header.c_str(), tag.c_str());
	else
	  (m_priv->table[current_header])[tag] = setting;

	m_priv->log->debug("new tag: \"%s\" = \"%s\"",
			  tag.c_str(), setting.c_str());

      }

    } // until the file ends

  } catch (...) {
    // In case there are exceptions.
  }
}

const std::string& ShibINI::get (const string& header, const string& tag)
{
  refresh();

  static string empty = "";

  string h = header;
  string t = tag;

  if (!m_priv->cs) {
    to_lowercase (h);
    to_lowercase (t);
  }

  if (!exists(h)) return empty;

  map<string,string>::const_iterator i = m_priv->table[h].find(t);
  if (i == m_priv->table[h].end())
    return empty;
  return i->second;
}

bool ShibINI::exists(const std::string& header)
{
  refresh();

  string h = header;
  if (!m_priv->cs) to_lowercase (h);

  return (m_priv->table.find(h) != m_priv->table.end());
}

bool ShibINI::exists(const std::string& header, const std::string& tag)
{
  refresh();

  string h = header;
  string t = tag;

  if (!m_priv->cs) {
    to_lowercase (h);
    to_lowercase (t);
  }

  if (!exists(h)) return false;
  return (m_priv->table[h].find(t) != m_priv->table[h].end());
}

bool ShibINI::get_tag (string& header, string& tag, bool try_general, string* result)
{
  if (!result) return false;

  refresh();

  if (exists (header, tag)) {
    *result = get (header, tag);
    return true;
  }
  if (try_general && exists (SHIBTARGET_GENERAL, tag)) {
    *result = get (SHIBTARGET_GENERAL, tag);
    return true;
  }
  return false;
}


void ShibINI::dump (ostream& os)
{
  refresh();

  os << "File: " << m_priv->file << "\n";
  os << "Case-Sensitive: " << ( m_priv->cs ? "Yes\n" : "No\n" );
  os << "File Entries:\n";

  for (map<string, map<string, string> >::const_iterator i = m_priv->table.begin();
       i != m_priv->table.end(); i++) {

    os << "[" << i->first << "]\n";

    for (map<string,string>::const_iterator j=i->second.begin();
	 j != i->second.end(); j++) {

      os << "  " << j->first << " = " << j->second << "\n";
    }
  }

  os << "END\n";
}

ShibINI::Iterator* ShibINI::header_iterator()
{
  refresh();
  HeaderIterator* iter = new HeaderIterator(m_priv);
  return (ShibINI::Iterator*) iter;
}

ShibINI::Iterator* ShibINI::tag_iterator(const std::string& header)
{
  refresh();
  TagIterator* iter = new TagIterator(m_priv, header);
  return (ShibINI::Iterator*) iter;
}

HeaderIterator::HeaderIterator (ShibINIPriv* inip)
{
  ini = inip;
  valid = false;
}

const string* HeaderIterator::begin ()
{
  iter = ini->table.begin();
  if (iter == ini->table.end()) {
    valid = false;
    return 0;
  }
  valid = true;
  return &iter->first;
}

const string* HeaderIterator::next ()
{
  if (!valid)
    return 0;
  iter++;
  if (iter == ini->table.end()) {
    valid = false;
    return 0;
  }
  return &iter->first;
}

TagIterator::TagIterator (ShibINIPriv* inip, const string& headerp)
  : header(headerp)
{
  ini = inip;
  valid = false;
}

const string* TagIterator::begin ()
{
  iter = ini->table[header].begin();
  if (iter == ini->table[header].end()) {
    valid = false;
    return 0;
  }
  valid = true;
  return &iter->first;
}

const string* TagIterator::next ()
{
  if (!valid)
    return 0;
  iter++;
  if (iter == ini->table[header].end()) {
    valid = false;
    return 0;
  }
  return &iter->first;
}

bool ShibINI::boolean(string& value)
{
  const char* v = value.c_str();
  if (!strncasecmp (v, "on", 2) || !strncasecmp (v, "true", 4))
    return true;
  return false;
}

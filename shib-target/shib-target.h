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
 * shib-target.h -- top-level header file for the SHIB Common Target Library
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#ifndef SHIB_TARGET_H
#define SHIB_TARGET_H

#ifdef __cplusplus
# include <saml/saml.h>
# include <shib/shib.h>
#endif

#ifdef WIN32
# ifndef SHIBTARGET_EXPORTS
#  define SHIBTARGET_EXPORTS __declspec(dllimport)
# endif
#else
# define SHIBTARGET_EXPORTS
#endif

#include <shib-target/shibrpc.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32

#include <winsock.h>
typedef SOCKET ShibSocket;
typedef u_short ShibSockName;
#define SHIB_SHAR_SOCKET 12345  /* shar portnumber */

#else  /* UNIX */

typedef int ShibSocket;
typedef char * ShibSockName;
#define SHIB_SHAR_SOCKET "/tmp/shar-socket"

#endif

/* shib-rpcutil.c */

/* Create an RPC Client handle for the _connected_ socket sock, attaching
 * the RPC program and version.
 *
 * returns a CLIENT on success, or NULL on error.  The caller can
 * call clnt_pcreateerror ("<string>") to output an error message from
 * the RPC library.
 */
SHIBTARGET_EXPORTS CLIENT * shibrpc_client_create (ShibSocket sock, u_long program, u_long version);

/* shib-sock.c */

/* Create a new socket and put it into sock.
 *
 * Returns 0 on success, non-zero on error 
 */
SHIBTARGET_EXPORTS int shib_sock_create (ShibSocket *sock);

/*
 * bind the socket s to the "port" name.
 *
 * Returns 0 on success; non-zero on error.
 *
 * SIDE EFFECT: On error, the socket is closed!
 */
SHIBTARGET_EXPORTS int shib_sock_bind (ShibSocket s, ShibSockName name);

/*
 * connect the socket s to the "port" name on the local host.
 *
 * Returns 0 on success; non-zero on error.
 */
SHIBTARGET_EXPORTS int shib_sock_connect (ShibSocket s, ShibSockName name);

/*
 * accept a connection.  Returns 0 on success, non-zero on failure.
 */
SHIBTARGET_EXPORTS int shib_sock_accept (ShibSocket listener, ShibSocket* s);

/*
 * close the socket
 */
SHIBTARGET_EXPORTS void shib_sock_close (ShibSocket s, ShibSockName name);

/* shib-target.cpp */

/* application names */
#define SHIBTARGET_GENERAL  "general"
#define SHIBTARGET_SHAR     "shar"
#define SHIBTARGET_SHIRE    "shire"
#define SHIBTARGET_RM       "rm"
#define SHIBTARGET_POLICIES "policies"

/* configuration tags */
#define SHIBTARGET_TAG_LOGGER   "logger"
#define SHIBTARGET_TAG_SCHEMAS  "schemadir"
#define SHIBTARGET_TAG_CERTFILE "certfile"
#define SHIBTARGET_TAG_KEYFILE  "keyfile"
#define SHIBTARGET_TAG_KEYPASS  "keypass"
#define SHIBTARGET_TAG_CALIST   "calist"

#define SHIBTARGET_TAG_AATIMEOUT    "AATimeout"
#define SHIBTARGET_TAG_AACONNECTTO  "AAConnectTimeout"
#define SHIBTARGET_TAG_SAMLCOMPAT   "SAMLCompat"

#define SHIBTARGET_TAG_METADATA "metadata"

#define SHIBTARGET_TAG_DEFAULTLIFE  "defaultLife"

#define SHIBTARGET_TAG_CACHETYPE    "cacheType"
#define SHIBTARGET_TAG_CACHECLEAN   "cacheClean"
#define SHIBTARGET_TAG_CACHETIMEOUT "cacheTimeout"

#define SHIBTARGET_TAG_REQATTRS     "requestAttributes"

/* initialize and finalize the target library (return 0 on success, 1 on failure) */
SHIBTARGET_EXPORTS int shib_target_initialize (const char* application, const char* ini_file);
SHIBTARGET_EXPORTS void shib_target_finalize (void);
SHIBTARGET_EXPORTS ShibSockName shib_target_sockname(void);

#ifdef __cplusplus
}


namespace shibtarget {
  class ResourcePriv;
  class SHIBTARGET_EXPORTS Resource
  {
  public:
    Resource(const char* resource_url);
    Resource(std::string resource_url);
    ~Resource();

    const char* getResource() const;
    const char* getURL() const;
    bool equals(Resource*) const;
    saml::Iterator<saml::SAMLAttribute*> getDesignators() const;

  private:
    ResourcePriv *m_priv;
  };

  class RPCHandleInternal;
  class SHIBTARGET_EXPORTS RPCHandle
  {
  public:
    RPCHandle(ShibSockName shar, u_long program, u_long version);
    ~RPCHandle();

    CLIENT *	connect(void);	/* locks the HANDLE and returns the CLIENT */
    void	release(void);	/* unlocks the HANDLE */
    void	disconnect(void); /* disconnects */

  private:
    RPCHandleInternal *m_priv;
  };

  class SHIBTARGET_EXPORTS ShibTargetException : public std::exception
  {
  public:
    explicit ShibTargetException() { m_code = SHIBRPC_OK; }
    explicit ShibTargetException(ShibRpcStatus code, const char* msg,
				 const XMLCh* origin = NULL)
	{ m_code = code; if (msg) m_msg=msg; if (origin) m_origin = origin; }
    explicit ShibTargetException(ShibRpcStatus code, const std::string& msg,
				 const XMLCh* origin = NULL) : m_msg(msg)
	{ m_code=code; if(origin) m_origin = origin; }
    virtual ~ShibTargetException() throw () {}
    virtual const char* what() const throw () { return (m_msg.c_str()); }
    virtual ShibRpcStatus which() const throw () { return (m_code); }
    virtual const XMLCh* where() const throw () { return m_origin.c_str(); }

  private:
    ShibRpcStatus	m_code;
    std::string		m_msg;
    saml::xstring	m_origin;
  };

  class RPCErrorPriv;
  class SHIBTARGET_EXPORTS RPCError
  {
  public:
    RPCError() { init(0, "", NULL); }
    RPCError(ShibRpcError* error);
    RPCError(int s, char const* st, const XMLCh* orig = NULL) { init (s,st,orig); }
    RPCError(ShibTargetException &exp) { init(exp.which(), exp.what(), exp.where()); }
    ~RPCError();

    bool	isError();
    bool	isRetryable();

    // Return a set of strings that corresponds to the type, text, and desc
    const char* getType();
    const char* getText();
    const char* getDesc();
    std::string getOriginErrorURL();
    std::string getOriginContactName();
    std::string getOriginContactEmail();
    int getCode();

  private:
    void init(int stat, char const* msg, const XMLCh* origin);
    RPCErrorPriv* m_priv;
  };

  class SHIBTARGET_EXPORTS SHIREConfig
  {
  public:
    bool	checkIPAddress;
    time_t	lifetime;
    time_t	timeout;
  };

  class SHIREPriv;
  class SHIBTARGET_EXPORTS SHIRE
  {
  public:
    SHIRE(RPCHandle *rpc, SHIREConfig config, std::string shire_url);
    ~SHIRE();

    RPCError* sessionIsValid(const char* cookie, const char* ip, const char* url);
    RPCError* sessionCreate(const char* post, const char* ip,
			     std::string &cookie);
  private:
    SHIREPriv *m_priv;
  };

  class SHIBTARGET_EXPORTS RMConfig
  {
  public:
    bool	checkIPAddress;
  };

  class RMPriv;
  class SHIBTARGET_EXPORTS RM
  {
  public:
    RM(RPCHandle *rpc, RMConfig config);
    ~RM();

    RPCError* getAssertions(const char* cookie, const char* ip,
			    const char* url,
			    std::vector<saml::SAMLAssertion*> &assertions,
			    saml::SAMLAuthenticationStatement **statement = NULL);
    static void serialize(saml::SAMLAssertion &assertion, std::string &result);
    static saml::Iterator<saml::SAMLAttribute*> getAttributes(saml::SAMLAssertion &assertion);
  private:
    RMPriv *m_priv;
  };

  class ShibINIPriv;
  class SHIBTARGET_EXPORTS ShibINI {
  public:
    ShibINI (std::string& file, bool case_sensitive = true) { init(file,case_sensitive); }
    ShibINI (const char *file, bool case_sensitive = true) {
      std::string f = file;
      init(f, case_sensitive);
    }
    ~ShibINI ();

    void refresh(void);

    const std::string get (const std::string& header, const std::string& tag);
    const std::string get (const char* header, const char* tag) {
      std::string h = header, t = tag;
      return get(h,t);
    }

    const std::string operator() (const std::string& header, const std::string& tag)  {
      return get(header,tag);
    }
    const std::string operator() (const char* header, const char* tag) {
      std::string h = header, t = tag;
      return get(h,t);
    }

    bool exists(const std::string& header);
    bool exists(const std::string& header, const std::string& tag);

    bool exists(const char* header) {
      std::string s = header;
      return exists(s);
    }
    bool exists(const char* header, const char* tag) {
      std::string h = header, t = tag;
      return exists(h,t);
    }

    // Special method to look for a tag in one header and maybe in the
    // 'SHIBTARGET_GENERAL' header
    bool get_tag(std::string& header, std::string& tag, bool try_general,
		 std::string* result);

    bool get_tag(std::string& header, const char* tag, bool try_general,
		 std::string* result) {
      std::string t = tag;
      return get_tag (header,t,try_general,result);
    }

    bool get_tag(const char* header, const char* tag, bool try_general,
		 std::string* result) {
      std::string h = header, t = tag;
      return get_tag (h,t,try_general,result);
    }

    // Dump out the inifile to the output stream
    void dump(std::ostream& os);

    // Iterators

    // The begin() functions reset the iterator and return the first element
    // (or 0 if there are no elements.)
    // The next() functions return the next element, or 0 if there are no
    // elements left.
    //
    // Example:
    // for (const foo* current = begin(); current; current = next()) {
    //   ...
    // }
    //
    // NOTE: Holding an Iterator will lock the INI file and cause it to
    // stop updating itself.  You should destroy the iterator as soon as
    // you are done with it.
    //
    // ALSO NOTE: the string* returned from the Iterator is only valid
    // while you hold the iterator.  You should copy the de-reference
    // of the pointer to your own copy if you want to keep the string.

    class SHIBTARGET_EXPORTS Iterator {
    public:
      virtual ~Iterator() {}
      virtual const std::string* begin() = 0;
      virtual const std::string* next() = 0;
    };

    Iterator* header_iterator();
    Iterator* tag_iterator(const std::string& header);

    static bool boolean(std::string& value);

  private:
    ShibINIPriv *m_priv;
    void init(std::string& file, bool case_sensitive);
  };

  class ShibMLPPriv;
  class SHIBTARGET_EXPORTS ShibMLP {
  public:
    ShibMLP();
    ~ShibMLP();

    void insert (const std::string& key, const std::string& value);
    void insert (const std::string& key, const char* value) {
      std::string v = value;
      insert (key, v);
    }
    void insert (const char* key, const std::string& value) {
      std::string k = key;
      insert (k, value);
    }
    void insert (const char* key, const char* value) {
      std::string k = key, v = value;
      insert(k,v);
    }
    void insert (RPCError& e);

    void clear () { m_map.clear(); }

    std::string run (std::istream& s) const;
    std::string run (const std::string& input) const;
    std::string run (const char* input) const {
      std::string i = input;
      return run(i);
    }

  private:
    ShibMLPPriv *m_priv;
    std::map<std::string,std::string> m_map;
  };

  class SHIBTARGET_EXPORTS ShibTargetConfig
  {
  public:
    static void preinit();
    static ShibTargetConfig& init(const char* app_name, const char* inifile);
    static ShibTargetConfig& getConfig();
    virtual void init() = 0;
    virtual void shutdown() = 0;
    virtual ~ShibTargetConfig();
    virtual ShibINI& getINI() = 0;
    virtual saml::Iterator<const XMLCh*> getPolicies() = 0;
    
    ShibSockName m_SocketName;
  };

} // namespace
#endif

#endif /* SHIB_TARGET_H */

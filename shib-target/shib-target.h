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
CLIENT * shibrpc_client_create (ShibSocket sock, u_long program, u_long version);

/* shib-sock.c */

/* Create a new socket and put it into sock.
 *
 * Returns 0 on success, non-zero on error 
 */
int shib_sock_create (ShibSocket *sock);

/*
 * bind the socket s to the "port" name.
 *
 * Returns 0 on success; non-zero on error.
 *
 * SIDE EFFECT: On error, the socket is closed!
 */
int shib_sock_bind (ShibSocket s, ShibSockName name);

/*
 * connect the socket s to the "port" name on the local host.
 *
 * Returns 0 on success; non-zero on error.
 */
int shib_sock_connect (ShibSocket s, ShibSockName name);

/*
 * accept a connection.  Returns 0 on success, non-zero on failure.
 */
int shib_sock_accept (ShibSocket listener, ShibSocket* s);

/*
 * close the socket
 */
void shib_sock_close (ShibSocket s, ShibSockName name);

/* shib-target.cpp */

/* application names */
#define SHIBTARGET_GENERAL  "general"
#define SHIBTARGET_SHAR     "shar"
#define SHIBTARGET_SHIRE    "shire"
#define SHIBTARGET_RM		 "rm"
#define SHIBTARGET_POLICIES "policies"

/* configuration tags */
#define SHIBTARGET_TAG_LOGGER   "logger"
#define SHIBTARGET_TAG_SCHEMAS	 "schemadir"
#define SHIBTARGET_TAG_CERTFILE "certfile"
#define SHIBTARGET_TAG_KEYFILE  "keyfile"
#define SHIBTARGET_TAG_KEYPASS  "keypass"
#define SHIBTARGET_TAG_CALIST   "calist"

#define SHIBTARGET_TAG_AATIMEOUT    "AATimeout"
#define SHIBTARGET_TAG_AACONNECTTO  "AAConnectTimeout"
#define SHIBTARGET_TAG_SAMLCOMPAT   "SAMLCompat"

#define SHIBTARGET_TAG_AAP      "aap-uri"
#define SHIBTARGET_TAG_METADATA "metadata"

#define SHIBTARGET_TAG_DEFAULTLIFE  "defaultLife"

#define SHIBTARGET_TAG_CACHETYPE    "cacheType"
#define SHIBTARGET_TAG_CACHECLEAN   "cacheClean"
#define SHIBTARGET_TAG_CACHETIMEOUT "cacheTimeout"

#define SHIBTARGET_TAG_REQATTRS     "requestAttributes"

/* initialize and finalize the target library (return 0 on success, 1 on failure) */
int shib_target_initialize (const char* application, const char* ini_file);
void shib_target_finalize (void);
ShibSockName shib_target_sockname(void);

#ifdef __cplusplus
}


namespace shibtarget {
  class ResourcePriv;
  class Resource
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
  class RPCHandle
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

  class ShibTargetException : public std::exception
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
  class RPCError
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

  class SHIREConfig
  {
  public:
    bool	checkIPAddress;
    time_t	lifetime;
    time_t	timeout;
  };

  class SHIREPriv;
  class SHIRE
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

  class RMConfig
  {
  public:
    bool	checkIPAddress;
  };

  class RMPriv;
  class RM
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
  class ShibINI {
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

    class Iterator {
    public:
      virtual ~Iterator() = 0;
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
  class ShibMLP {
  public:
    ShibMLP();
    ~ShibMLP();

    void insert (const std::string& key, const std::string& value) { m_map[key] = value; }
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

  class ShibTargetConfig
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

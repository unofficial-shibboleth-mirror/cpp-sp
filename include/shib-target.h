/*
 * shib-common.h -- top-level header file for the SHIB Common Target Library
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#ifndef SHIB_COMMON_H
#define SHIB_COMMON_H

#include "shibrpc.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32

#error "Need to define ShibSocket"
typedef in_port_t ShibSockName;
#define SHIB_SHAR_SOCKET 12345	/* shar portnumber */

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


/* shib-target.cpp */

/* application names */
#define SHIBTARGET_GENERAL	"general"
#define SHIBTARGET_SHAR		"shar"
#define SHIBTARGET_SHIRE	"shire"
#define SHIBTARGET_RM		"rm"

/* configuration headers */
#define SHIBTARGET_HTTP		"http"

/* configuration tags */
#define SHIBTARGET_TAG_LOGGER	"logger"
#define SHIBTARGET_TAG_SCHEMAS	"schemadir"
#define SHIBTARGET_TAG_CERTFILE	"certfile"
#define SHIBTARGET_TAG_KEYFILE	"keyfile"
#define SHIBTARGET_TAG_KEYPASS	"keypass"
#define SHIBTARGET_TAG_CALIST	"calist"

/* initialize and finalize the target library (return 0 on success, 1 on failure) */
int shib_target_initialize (const char* application, const char* ini_file);
void shib_target_finalize (void);

#ifdef __cplusplus
}


// SAML Runtime
#include <saml.h>
#include <shib.h>

namespace shibtarget {
  class ResourcePriv;
  class Resource
  {
  public:
    Resource(const char* resource_url);
    Resource(std::string resource_url);
    ~Resource();

    const char* getResource();
    const char* getURL();
    bool equals(Resource*);

  private:
    ResourcePriv *m_priv;
  };


  class CCache;
  class CCacheEntry
  {
  public:
    virtual ~CCacheEntry();

    virtual saml::Iterator<saml::SAMLAssertion*> getAssertions(Resource& resource) = 0;
    virtual bool isSessionValid(time_t lifetime, time_t timeout) = 0;
    virtual const char* getClientAddress() = 0;

    static CCacheEntry* getInstance(saml::SAMLAuthenticationStatement *s,
				    const char *client_addr);

    friend class CCache;
  protected:
    // this should only be called by CCache::insert()
    virtual void setCache(CCache* cache) = 0;
  };
    
  class CCache
  {
  public:
    virtual ~CCache();

    virtual saml::SAMLBinding* getBinding(const XMLCh* bindingProt) = 0;
    virtual CCacheEntry* find(const char* key) = 0;
    virtual void insert(const char* key, CCacheEntry* entry) = 0;
    virtual void remove(const char* key) = 0;
    
    static CCache* getInstance();

  protected:
    // special function to call over to CCacheEntry::setCache()
    void setCache(CCacheEntry* entry);
  };    

  extern CCache* g_shibTargetCCache;

  class RPCHandleInternal;
  class RPCHandle
  {
  public:
    RPCHandle(ShibSockName shar, u_long program, u_long version);
    ~RPCHandle();

    CLIENT *	connect(void);
    void	disconnect(void);

  private:
    RPCHandleInternal *m_priv;
  };

  class ShibTargetException : public std::exception
  {
  public:
    explicit ShibTargetException() { m_code = SHIBRPC_OK; m_msg=""; }
    explicit ShibTargetException(ShibRpcStatus code, const char* msg) { m_code = code; if (msg) m_msg=msg; }
    explicit ShibTargetException(ShibRpcStatus code, const std::string& msg) : m_msg(msg) { m_code=code; }
    virtual ~ShibTargetException() throw () {}
    virtual const char* what() const throw () { return (m_msg.c_str()); }
    virtual ShibRpcStatus which() const throw () { return (m_code); }

  private:
    ShibRpcStatus	m_code;
    std::string		m_msg;
  };

  class RPCErrorPriv;
  class RPCError
  {
  public:
    RPCError() { init(0,""); }
    RPCError(int s, char const* st) { init(s,st); }
    RPCError(ShibTargetException &exp) { init(exp.which(), exp.what()); }
    ~RPCError();

    bool	isError() { return (status != 0); }
    bool	isRetryable();

    // Return a string that corresponds to the "status"
    const char* toString();

    int		status;
    std::string	error_msg;
    saml::SAMLException* m_except;

  private:
    void init(int code, char const* msg);
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

    RPCError* sessionIsValid(const char* cookie, const char* ip);
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
			    std::vector<saml::SAMLAssertion*> &assertions);
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

    const std::string& get (const std::string& header, const std::string& tag) const;
    const std::string& get (const char* header, const char* tag) const {
      std::string h = header, t = tag;
      return get(h,t);
    }

    const std::string& operator() (const std::string& header, const std::string& tag) const {
      return get(header,tag);
    }
    const std::string& operator() (const char* header, const char* tag) const {
      std::string h = header, t = tag;
      return get(h,t);
    }

    bool exists(const std::string& header) const;
    bool exists(const std::string& header, const std::string& tag) const;

    bool exists(const char* header) const {
      std::string s = header;
      return exists(s);
    }
    bool exists(const char* header, const char* tag) const {
      std::string h = header, t = tag;
      return exists(h,t);
    }

    // Special method to look for a tag in one header and maybe in the
    // 'SHIBTARGET_GENERAL' header
    bool get_tag(std::string& header, std::string& tag, bool try_general,
		 std::string* result) const;

    bool get_tag(std::string& header, const char* tag, bool try_general,
		 std::string* result) const {
      std::string t = tag;
      return get_tag (header,t,try_general,result);
    }

    bool get_tag(const char* header, const char* tag, bool try_general,
		 std::string* result) const {
      std::string h = header, t = tag;
      return get_tag (h,t,try_general,result);
    }

    // Dump out the inifile to the output stream
    void dump(std::ostream& os) const;

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

    class Iterator {
    public:
      virtual const std::string* begin() = 0;
      virtual const std::string* next() = 0;
    };

    Iterator* header_iterator() const;
    Iterator* tag_iterator(const std::string& header) const;

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
    static ShibTargetConfig& init(const char* app_name, const char* inifile);
    virtual void shutdown() = 0;
    virtual ShibINI& getINI() = 0;
  };

} // namespace
#endif

#endif /* SHIB_COMMON_H */

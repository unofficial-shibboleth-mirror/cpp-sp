/*
 * shib_rpc.x: generic shib RPC definitions for target communication
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#ifdef RPC_XDR
%
%/* sometimes xdr_enum_t is not defined properly */
%#ifndef xdr_enum_t
%#define xdr_enum_t xdr_enum
%#endif
%
#endif

enum ShibRpcStatus {
  SHIBRPC_OK = 0,
  SHIBRPC_UNKNOWN_ERROR = 1,
  SHIBRPC_INTERNAL_ERROR = 2,
  SHIBRPC_XML_EXCEPTION = 3,
  SHIBRPC_SAX_EXCEPTION = 4,
  SHIBRPC_SAML_EXCEPTION = 5,

  /* session_is_valid errors */
  SHIBRPC_NO_SESSION = 10,
  SHIBRPC_SESSION_EXPIRED = 11,
  SHIBRPC_IPADDR_MISMATCH = 12,

  /* new_session errors */
  SHIBRPC_IPADDR_MISSING = 20,
  SHIBRPC_RESPONSE_MISSING = 21,
  SHIBRPC_ASSERTION_REPLAYED = 22

  /* get_attrs errors */
};

/* Hold an error and origin */
struct ShibRpcErr {
  string	error<>;
  string	origin<>;
};

/* A type for RPC Errors */
union ShibRpcError switch(ShibRpcStatus status) {
 case SHIBRPC_OK:
   void;
 default:
   ShibRpcErr	e;
};

/* A type to pass a Cookie, which contains the HTTP cookie string
 * and the IP Address of the client */
struct ShibRpcHttpCookie_1 {
  string	cookie<>;
  string	client_addr<>;
};

struct ShibRpcXML {
  string	xml_string<>;
};

/* function argument and response structures */

struct shibrpc_session_is_valid_args_1 {
  ShibRpcHttpCookie_1	cookie;
  string		application_id<>;
  bool			checkIPAddress;
  long			lifetime;
  long			timeout;
};

struct shibrpc_session_is_valid_ret_1 {
  ShibRpcError	status;
};

struct shibrpc_new_session_args_1 {
  string	application_id<>;
  string	shire_location<>;
  string	saml_post<>;
  string	client_addr<>;
  bool		checkIPAddress;
};

struct shibrpc_new_session_ret_1 {
  ShibRpcError	status;
  string	cookie<>;
};


struct shibrpc_get_assertions_args_1 {
  ShibRpcHttpCookie_1	cookie;
  bool			checkIPAddress;
  string		application_id<>;
};

struct shibrpc_get_assertions_ret_1 {
  ShibRpcError		status;
  ShibRpcXML		auth_statement;
  ShibRpcXML		assertions<>;
};

/* Define the Shib Target RPC interface */
program SHIBRPC_PROG {
  version SHIBRPC_VERS_1 {

    /* Ping the rpcsvc to make sure it is alive. */
    int shibrpc_ping (int) = 0;

    /* SHIRE RPCs */

    /* Is the HTTP Cookie valid? Is the session still active?
     * Returns 0 for TRUE, a non-zero error code for FALSE */
    shibrpc_session_is_valid_ret_1 shibrpc_session_is_valid (shibrpc_session_is_valid_args_1) = 1;

    /* Create a new session for this user (SAML POST Profile Consumer) */
    shibrpc_new_session_ret_1 shibrpc_new_session (shibrpc_new_session_args_1)
      = 2;

    /* RM RPCs */

    /* Get the assertions from the SHAR */
    shibrpc_get_assertions_ret_1 shibrpc_get_assertions (shibrpc_get_assertions_args_1) = 3;

  } = 1;
} = 123456;			/* XXX: Pick an RPC Program Number */

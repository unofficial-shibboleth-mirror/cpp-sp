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
  SHIBRPC_IPADDR_MISMATCH = 2,
  SHIBRPC_NO_SESSION = 3,
  SHIBRPC_XML_EXCEPTION = 4,
  SHIBRPC_SAML_EXCEPTION = 5,
  SHIBRPC_INTERNAL_ERROR = 6,
  SHIBRPC_SAX_EXCEPTION = 7,

  /* session_is_valid errors */
  SHIBRPC_SESSION_EXPIRED = 10,

  /* new_session errors */
  SHIBRPC_AUTHSTATEMENT_MISSING = 20,
  SHIBRPC_IPADDR_MISSING = 21,
  SHIBRPC_RESPONSE_MISSING = 22,
  SHIBRPC_ASSERTION_MISSING = 23,
  SHIBRPC_ASSERTION_REPLAYED = 24

  /* get_attrs errors */
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
  string		url<>;
  bool			checkIPAddress;
  long			lifetime;
  long			timeout;
};

struct shibrpc_session_is_valid_ret_1 {
  ShibRpcStatus	status;
  string	error_msg<>;
};

struct shibrpc_new_session_args_1 {
  string	shire_location<>;
  string	saml_post<>;
  string	client_addr<>;
  bool		checkIPAddress;
};

struct shibrpc_new_session_ret_1 {
  ShibRpcStatus	status;
  string	error_msg<>;
  string	cookie<>;
};


struct shibrpc_get_assertions_args_1 {
  ShibRpcHttpCookie_1	cookie;
  bool			checkIPAddress;
  string		url<>;
};

struct shibrpc_get_assertions_ret_1 {
  ShibRpcStatus		status;
  string		error_msg<>;
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

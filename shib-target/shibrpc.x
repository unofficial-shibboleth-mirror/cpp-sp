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

/* Hold an error, providerId, and support data */
struct ShibRpcErr {
  string	error<>;
  string	provider<>;
  string	url<>;
  string	contact<>;
  string	email<>;
};

/* A type for RPC Errors */
union ShibRpcError switch(ShibRpcStatus status) {
 case SHIBRPC_OK:
   void;
 default:
   ShibRpcErr	e;
};

struct ShibRpcXML {
  string	xml_string<>;
};

/* function argument and response structures */

struct shibrpc_new_session_args_2 {
  string	application_id<>;
  string	packet<>;
  string	recipient<>;
  string	client_addr<>;
  bool		checkIPAddress;
};

struct shibrpc_new_session_ret_2 {
  ShibRpcError	status;
  string	target<>;
  string	cookie<>;
};

struct shibrpc_get_session_args_2 {
  string		application_id<>;
  string		cookie<>;
  string		client_addr<>;
  bool			checkIPAddress;
  long			lifetime;
  long			timeout;
};

struct shibrpc_get_session_ret_2 {
  ShibRpcError	status;
  ShibRpcXML	auth_statement;
  ShibRpcXML	assertions<>;
};


/* Define the Shib Target RPC interface */
program SHIBRPC_PROG {
  version SHIBRPC_VERS_2 {

    /* Ping the rpcsvc to make sure it is alive. */
    int shibrpc_ping (int) = 0;

    /* Session Cache Remoting RPCs */

    /* Create a new session for this user (SAML Browser Profile Consumer) */
    shibrpc_new_session_ret_2 shibrpc_new_session (shibrpc_new_session_args_2) = 1;

    /* Validate and access data associated with existing session.
     * Returns 0 for TRUE, a non-zero error code for FALSE */
    shibrpc_get_session_ret_2 shibrpc_get_session (shibrpc_get_session_args_2) = 2;

  } = 2;
} = 123456;			/* Arbitrary RPC Program Number */

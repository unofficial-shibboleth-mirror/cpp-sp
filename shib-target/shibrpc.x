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

/* enumerate profiles/bindings to support */
enum ShibProfile {
  PROFILE_UNSPECIFIED = 0,
  SAML_10_POST = 1,
  SAML_10_ARTIFACT = 2,
  SAML_11_POST = 4,
  SAML_11_ARTIFACT = 8,
  SAML_20_SSO = 16
};

/* function argument and response structures */

struct shibrpc_statemgr_args_2 {
  string	application_id<>;
  string	packet<>;				/* opaque state to manage */
  string	client_addr<>;
};

struct shibrpc_statemgr_ret_2 {
  ShibRpcError	status;
  string	cookie<>;				/* state token returned to caller */
};

struct shibrpc_new_session_args_2 {
  int		supported_profiles;		/* bitmask of supported profiles */
  string	application_id<>;
  string	packet<>;				/* profile input packet from client */
  string	cookie<>;				/* statemgr token, if any */
  string	recipient<>;			/* endpoint that received packet */
  string	client_addr<>;
};

struct shibrpc_new_session_ret_2 {
  ShibRpcError	status;
  string	target<>;				/* profile-specific state token from client */
  string	packet<>;				/* state token recovered by statemgr, if any */
  string	cookie<>;				/* session key manufactured for client */
};

struct shibrpc_get_session_args_2 {
  string		application_id<>;
  string		cookie<>;			/* session key provided by client */
  string		client_addr<>;
};

struct shibrpc_get_session_ret_2 {
  ShibRpcError	status;
  ShibProfile	profile;				/* profile used in creating session */
  string		provider_id<>;			/* authenticating IdP */
  string		auth_statement<>;		/* SAML authn statement */
  string		attr_response_pre<>;	/* SAML attr assertions as received */
  string		attr_response_post<>;	/* SAML attr assertions post-filtering */
};


/* Define the Shib Target RPC interface */
program SHIBRPC_PROG {
  version SHIBRPC_VERS_2 {

    /* Ping the rpcsvc to make sure it is alive. */
    int shibrpc_ping (int) = 0;

    /* Session Cache Remoting RPCs */

    /* Create a new session for this user (SAML Browser Profile Consumer) */
    shibrpc_new_session_ret_2 shibrpc_new_session (shibrpc_new_session_args_2) = 1;

    /* Validate and access data associated with existing session */
    shibrpc_get_session_ret_2 shibrpc_get_session (shibrpc_get_session_args_2) = 2;

	/* Post managed state information for later retrieval during session creation */
	shibrpc_statemgr_ret_2 shibrpc_statemgr (shibrpc_statemgr_args_2) = 3;

  } = 2;
} = 123456;			/* Arbitrary RPC Program Number */

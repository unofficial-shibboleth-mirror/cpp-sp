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

/* enumerate profiles/bindings to support */
enum ShibProfile {
  PROFILE_UNSPECIFIED = 0,
  SAML10_POST = 1,
  SAML10_ARTIFACT = 2,
  SAML11_POST = 4,
  SAML11_ARTIFACT = 8,
  SAML20_SSO = 16
};

/* function argument and response structures */

struct shibrpc_new_session_args_2 {
  int		supported_profiles;		/* bitmask of supported profiles */
  string	application_id<>;
  string	packet<>;				/* profile input packet from client */
  string	recipient<>;			/* endpoint that received packet */
  string	client_addr<>;
};

struct shibrpc_new_session_ret_2 {
  string	status<>;				/* empty string or a SAMLException */
  string	target<>;				/* profile-specific state token from client */
  string	cookie<>;				/* session key manufactured for client */
};

struct shibrpc_get_session_args_2 {
  string		application_id<>;
  string		cookie<>;			/* session key provided by client */
  string		client_addr<>;
};

struct shibrpc_get_session_ret_2 {
  string		status<>;				/* empty string or a SAMLException */
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

  } = 2;
} = 123456;			/* Arbitrary RPC Program Number */

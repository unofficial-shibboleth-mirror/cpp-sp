/*
 *  Copyright 2001-2005 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

/* function argument and response structures */

struct shibrpc_new_session_args_2 {
  int		supported_profiles;			/* bitmask of supported profiles */
  string	application_id<>;
  string	packet<>;					/* profile input packet from client */
  string	recipient<>;				/* endpoint that received packet */
  string	client_addr<>;
};

struct shibrpc_new_session_ret_2 {
  string	status<>;					/* empty string or a SAMLException */
  string	target<>;					/* profile-specific state token from client */
  string	cookie<>;					/* session key manufactured for client */
  string	provider_id<>;				/* authenticating IdP */
};

struct shibrpc_get_session_args_2 {
  string		application_id<>;
  string		cookie<>;				/* session key provided by client */
  string		client_addr<>;
};

struct shibrpc_get_session_ret_2 {
  string		status<>;				/* empty string or a SAMLException */
  int			profile;				/* profile used in creating session */
  string		provider_id<>;			/* authenticating IdP */
  string		auth_statement<>;		/* SAML authn statement */
  string		attr_response_pre<>;	/* SAML attr assertions as received */
  string		attr_response_post<>;	/* SAML attr assertions post-filtering */
};

struct shibrpc_end_session_args_2 {
  string		cookie<>;				/* session key provided by client */
};

struct shibrpc_end_session_ret_2 {
  string		status<>;				/* empty string or a SAMLException */
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
    
    /* End a session */
    shibrpc_end_session_ret_2 shibrpc_end_session (shibrpc_end_session_args_2) = 3;

  } = 2;
} = 123456;			/* Arbitrary RPC Program Number */

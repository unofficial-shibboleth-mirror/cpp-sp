/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#ifndef _SHIBRPC_H_RPCGEN
#define _SHIBRPC_H_RPCGEN

#include <rpc/rpc.h>

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif


enum ShibRpcStatus {
	SHIBRPC_OK = 0,
	SHIBRPC_UNKNOWN_ERROR = 1,
	SHIBRPC_INTERNAL_ERROR = 2,
	SHIBRPC_XML_EXCEPTION = 3,
	SHIBRPC_SAX_EXCEPTION = 4,
	SHIBRPC_SAML_EXCEPTION = 5,
	SHIBRPC_NO_SESSION = 10,
	SHIBRPC_SESSION_EXPIRED = 11,
	SHIBRPC_IPADDR_MISMATCH = 12,
	SHIBRPC_IPADDR_MISSING = 20,
	SHIBRPC_RESPONSE_MISSING = 21,
	SHIBRPC_ASSERTION_REPLAYED = 22,
};
typedef enum ShibRpcStatus ShibRpcStatus;

struct ShibRpcErr {
	char *error;
	char *origin;
};
typedef struct ShibRpcErr ShibRpcErr;

struct ShibRpcError {
	ShibRpcStatus status;
	union {
		ShibRpcErr e;
	} ShibRpcError_u;
};
typedef struct ShibRpcError ShibRpcError;

struct ShibRpcHttpCookie_1 {
	char *cookie;
	char *client_addr;
};
typedef struct ShibRpcHttpCookie_1 ShibRpcHttpCookie_1;

struct ShibRpcXML {
	char *xml_string;
};
typedef struct ShibRpcXML ShibRpcXML;

struct shibrpc_session_is_valid_args_1 {
	ShibRpcHttpCookie_1 cookie;
	char *application_id;
	bool_t checkIPAddress;
	long lifetime;
	long timeout;
};
typedef struct shibrpc_session_is_valid_args_1 shibrpc_session_is_valid_args_1;

struct shibrpc_session_is_valid_ret_1 {
	ShibRpcError status;
};
typedef struct shibrpc_session_is_valid_ret_1 shibrpc_session_is_valid_ret_1;

struct shibrpc_new_session_args_1 {
	char *application_id;
	char *shire_location;
	char *saml_post;
	char *client_addr;
	bool_t checkIPAddress;
};
typedef struct shibrpc_new_session_args_1 shibrpc_new_session_args_1;

struct shibrpc_new_session_ret_1 {
	ShibRpcError status;
	char *cookie;
};
typedef struct shibrpc_new_session_ret_1 shibrpc_new_session_ret_1;

struct shibrpc_get_assertions_args_1 {
	ShibRpcHttpCookie_1 cookie;
	bool_t checkIPAddress;
	char *application_id;
};
typedef struct shibrpc_get_assertions_args_1 shibrpc_get_assertions_args_1;

struct shibrpc_get_assertions_ret_1 {
	ShibRpcError status;
	ShibRpcXML auth_statement;
	struct {
		u_int assertions_len;
		ShibRpcXML *assertions_val;
	} assertions;
};
typedef struct shibrpc_get_assertions_ret_1 shibrpc_get_assertions_ret_1;

#define SHIBRPC_PROG 123456
#define SHIBRPC_VERS_1 1

#if defined(__STDC__) || defined(__cplusplus)
#define shibrpc_ping 0
extern  enum clnt_stat shibrpc_ping_1(int *, int *, CLIENT *);
extern  bool_t shibrpc_ping_1_svc(int *, int *, struct svc_req *);
#define shibrpc_session_is_valid 1
extern  enum clnt_stat shibrpc_session_is_valid_1(shibrpc_session_is_valid_args_1 *, shibrpc_session_is_valid_ret_1 *, CLIENT *);
extern  bool_t shibrpc_session_is_valid_1_svc(shibrpc_session_is_valid_args_1 *, shibrpc_session_is_valid_ret_1 *, struct svc_req *);
#define shibrpc_new_session 2
extern  enum clnt_stat shibrpc_new_session_1(shibrpc_new_session_args_1 *, shibrpc_new_session_ret_1 *, CLIENT *);
extern  bool_t shibrpc_new_session_1_svc(shibrpc_new_session_args_1 *, shibrpc_new_session_ret_1 *, struct svc_req *);
#define shibrpc_get_assertions 3
extern  enum clnt_stat shibrpc_get_assertions_1(shibrpc_get_assertions_args_1 *, shibrpc_get_assertions_ret_1 *, CLIENT *);
extern  bool_t shibrpc_get_assertions_1_svc(shibrpc_get_assertions_args_1 *, shibrpc_get_assertions_ret_1 *, struct svc_req *);
extern int shibrpc_prog_1_freeresult (SVCXPRT *, xdrproc_t, caddr_t);

#else /* K&R C */
#define shibrpc_ping 0
extern  enum clnt_stat shibrpc_ping_1();
extern  bool_t shibrpc_ping_1_svc();
#define shibrpc_session_is_valid 1
extern  enum clnt_stat shibrpc_session_is_valid_1();
extern  bool_t shibrpc_session_is_valid_1_svc();
#define shibrpc_new_session 2
extern  enum clnt_stat shibrpc_new_session_1();
extern  bool_t shibrpc_new_session_1_svc();
#define shibrpc_get_assertions 3
extern  enum clnt_stat shibrpc_get_assertions_1();
extern  bool_t shibrpc_get_assertions_1_svc();
extern int shibrpc_prog_1_freeresult ();
#endif /* K&R C */

/* the xdr functions */

#if defined(__STDC__) || defined(__cplusplus)
extern  bool_t xdr_ShibRpcStatus (XDR *, ShibRpcStatus*);
extern  bool_t xdr_ShibRpcErr (XDR *, ShibRpcErr*);
extern  bool_t xdr_ShibRpcError (XDR *, ShibRpcError*);
extern  bool_t xdr_ShibRpcHttpCookie_1 (XDR *, ShibRpcHttpCookie_1*);
extern  bool_t xdr_ShibRpcXML (XDR *, ShibRpcXML*);
extern  bool_t xdr_shibrpc_session_is_valid_args_1 (XDR *, shibrpc_session_is_valid_args_1*);
extern  bool_t xdr_shibrpc_session_is_valid_ret_1 (XDR *, shibrpc_session_is_valid_ret_1*);
extern  bool_t xdr_shibrpc_new_session_args_1 (XDR *, shibrpc_new_session_args_1*);
extern  bool_t xdr_shibrpc_new_session_ret_1 (XDR *, shibrpc_new_session_ret_1*);
extern  bool_t xdr_shibrpc_get_assertions_args_1 (XDR *, shibrpc_get_assertions_args_1*);
extern  bool_t xdr_shibrpc_get_assertions_ret_1 (XDR *, shibrpc_get_assertions_ret_1*);

#else /* K&R C */
extern bool_t xdr_ShibRpcStatus ();
extern bool_t xdr_ShibRpcErr ();
extern bool_t xdr_ShibRpcError ();
extern bool_t xdr_ShibRpcHttpCookie_1 ();
extern bool_t xdr_ShibRpcXML ();
extern bool_t xdr_shibrpc_session_is_valid_args_1 ();
extern bool_t xdr_shibrpc_session_is_valid_ret_1 ();
extern bool_t xdr_shibrpc_new_session_args_1 ();
extern bool_t xdr_shibrpc_new_session_ret_1 ();
extern bool_t xdr_shibrpc_get_assertions_args_1 ();
extern bool_t xdr_shibrpc_get_assertions_ret_1 ();

#endif /* K&R C */

#ifdef __cplusplus
}
#endif

#endif /* !_SHIBRPC_H_RPCGEN */

/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "shibrpc.h"
#include <stdio.h>
#include <stdlib.h>
#include <rpc/pmap_clnt.h>
#include <string.h>
#include <memory.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef SIG_PF
#define SIG_PF void(*)(int)
#endif

void
shibrpc_prog_1(struct svc_req *rqstp, register SVCXPRT *transp)
{
	union {
		int shibrpc_ping_1_arg;
		shibrpc_session_is_valid_args_1 shibrpc_session_is_valid_1_arg;
		shibrpc_new_session_args_1 shibrpc_new_session_1_arg;
		shibrpc_get_attrs_args_1 shibrpc_get_attrs_1_arg;
	} argument;
	union {
		int shibrpc_ping_1_res;
		shibrpc_session_is_valid_ret_1 shibrpc_session_is_valid_1_res;
		shibrpc_new_session_ret_1 shibrpc_new_session_1_res;
		shibrpc_get_attrs_ret_1 shibrpc_get_attrs_1_res;
	} result;
	bool_t retval;
	xdrproc_t _xdr_argument, _xdr_result;
	bool_t (*local)(char *, void *, struct svc_req *);

	switch (rqstp->rq_proc) {
	case shibrpc_ping:
		_xdr_argument = (xdrproc_t) xdr_int;
		_xdr_result = (xdrproc_t) xdr_int;
		local = (bool_t (*) (char *, void *,  struct svc_req *))shibrpc_ping_1_svc;
		break;

	case shibrpc_session_is_valid:
		_xdr_argument = (xdrproc_t) xdr_shibrpc_session_is_valid_args_1;
		_xdr_result = (xdrproc_t) xdr_shibrpc_session_is_valid_ret_1;
		local = (bool_t (*) (char *, void *,  struct svc_req *))shibrpc_session_is_valid_1_svc;
		break;

	case shibrpc_new_session:
		_xdr_argument = (xdrproc_t) xdr_shibrpc_new_session_args_1;
		_xdr_result = (xdrproc_t) xdr_shibrpc_new_session_ret_1;
		local = (bool_t (*) (char *, void *,  struct svc_req *))shibrpc_new_session_1_svc;
		break;

	case shibrpc_get_attrs:
		_xdr_argument = (xdrproc_t) xdr_shibrpc_get_attrs_args_1;
		_xdr_result = (xdrproc_t) xdr_shibrpc_get_attrs_ret_1;
		local = (bool_t (*) (char *, void *,  struct svc_req *))shibrpc_get_attrs_1_svc;
		break;

	default:
		svcerr_noproc (transp);
		return;
	}
	memset ((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		svcerr_decode (transp);
		return;
	}
	retval = (bool_t) (*local)((char *)&argument, (void *)&result, rqstp);
	if (retval > 0 && !svc_sendreply(transp, (xdrproc_t) _xdr_result, (char *)&result)) {
		svcerr_systemerr (transp);
	}
	if (!svc_freeargs (transp, (xdrproc_t) _xdr_argument, (caddr_t) &argument)) {
		fprintf (stderr, "%s", "unable to free arguments");
		exit (1);
	}
	if (!shibrpc_prog_1_freeresult (transp, _xdr_result, (caddr_t) &result))
		fprintf (stderr, "%s", "unable to free results");

	return;
}

/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "shibrpc.h"

/* sometimes xdr_enum_t is not defined properly */
#ifndef xdr_enum_t
#define xdr_enum_t xdr_enum
#endif


bool_t
xdr_ShibProfile (XDR *xdrs, ShibProfile *objp)
{
	register int32_t *buf;

	 if (!xdr_enum (xdrs, (enum_t *) objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_shibrpc_new_session_args_2 (XDR *xdrs, shibrpc_new_session_args_2 *objp)
{
	register int32_t *buf;

	 if (!xdr_int (xdrs, &objp->supported_profiles))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->application_id, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->packet, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->recipient, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->client_addr, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_shibrpc_new_session_ret_2 (XDR *xdrs, shibrpc_new_session_ret_2 *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->status, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->target, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->cookie, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_shibrpc_get_session_args_2 (XDR *xdrs, shibrpc_get_session_args_2 *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->application_id, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->cookie, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->client_addr, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_shibrpc_get_session_ret_2 (XDR *xdrs, shibrpc_get_session_ret_2 *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->status, ~0))
		 return FALSE;
	 if (!xdr_ShibProfile (xdrs, &objp->profile))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->provider_id, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->auth_statement, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->attr_response_pre, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->attr_response_post, ~0))
		 return FALSE;
	return TRUE;
}

/*********************************************************************
 * RPC for the Windows NT Operating System
 * 1993 by Martin F. Gergeleit
 * Users may use, copy or modify Sun RPC for the Windows NT Operating 
 * System according to the Sun copyright below.
 *
 * RPC for the Windows NT Operating System COMES WITH ABSOLUTELY NO 
 * WARRANTY, NOR WILL I BE LIABLE FOR ANY DAMAGES INCURRED FROM THE 
 * USE OF. USE ENTIRELY AT YOUR OWN RISK!!!
 *********************************************************************/

/* @(#)rpc.h	2.3 88/08/10 4.0 RPCSRC; from 1.9 88/02/08 SMI */
/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 *
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 *
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 *
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 *
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 *
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */

/*
 * rpc.h, Just includes the billions of rpc header files necessary to
 * do remote procedure calling.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */
#ifndef __RPC_HEADER__
#define __RPC_HEADER__

/* A bunch of defines to hide this implementation, to make sure it
 * doesn't shadow the system RPC library...
 */

#define clnttcp_create	onc_clnttcp_create
#define clnt_spcreateerror	onc_clnt_spcreateerror
#define svc_register	onc_svc_register
#define svc_getreqset	onc_svc_getreqset
#define svcfd_create    onc_svcfd_create

#ifndef FD_SETSIZE
# define FD_SETSIZE 1024
#endif


#ifdef WIN32

#include <stdlib.h>
#include <time.h>
#include <winsock.h>
#include <rpc/types.h>		/* some typedefs */
#include <process.h>

#define WSAerrno (WSAGetLastError())
#define gettimeofday(tv,tz) ((tv)->tv_sec = time(0), (tv)->tv_usec = 0)

#ifdef __cplusplus
extern "C" {
#define DOTS ...
#else
#define DOTS
#endif

extern int rpc_nt_init(void);
extern int rpc_nt_exit(void);
extern void nt_rpc_report(DOTS);

#include <rpc/bcopy.h>
extern int xdr_opaque_auth(DOTS);

#ifdef __cplusplus
};
#endif

#else
#include <rpc/types.h>		/* some typedefs */
#include <netinet/in.h>
#endif

/* external data representation interfaces */
#include <rpc/xdr.h>		/* generic (de)serializer */

/* Client side only authentication */
#include <rpc/auth.h>		/* generic authenticator (client side) */

/* Client side (mostly) remote procedure call */
#include <rpc/clnt.h>		/* generic rpc stuff */

/* semi-private protocol headers */
#include <rpc/rpc_msg.h>	/* protocol for rpc messages */
#include <rpc/auth_unix.h>	/* protocol for unix style cred */

/*
 *  Uncomment-out the next line if you are building the rpc library with
 *  DES Authentication (see the README file in the secure_rpc/ directory).
 */
/*#include <rpc/auth_des.h>	/* protocol for des style cred */

/* Server side only remote procedure callee */
#include <rpc/svc.h>		/* service manager and multiplexer */
#include <rpc/svc_auth.h>	/* service side authenticator */

#ifdef __cplusplus
extern "C" {
#endif

/* Oct 2004: Additions by Scott Cantor to support POSIX and Win32 threads. */
#ifdef WIN32
extern DWORD __thr_key;
extern CRITICAL_SECTION __thr_mutex;
#else
extern pthread_mutex_t __thr_mutex;
#endif

extern struct opaque_auth* _thr_null_auth(void);
extern struct rpc_createerr_t* _thr_rpc_createerr(void);
extern fd_set* _thr_svc_fdset(void);

#ifdef __cplusplus
}
#endif

#endif /* ndef __RPC_HEADER__ */

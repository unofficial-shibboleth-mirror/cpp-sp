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

/* @(#)rpc_commondata.c	2.1 88/07/29 4.0 RPCSRC */
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
#include <rpc/rpc.h>
#include <stdio.h>
/*
 * This file should only contain common data (global data) that is exported
 * by public interfaces 
 */

/* modified by Scott Cantor to make global data per-thread */

#ifndef WIN32
#include <pthread.h>
pthread_once_t __thr_onc_control = PTHREAD_ONCE_INIT;   /* insures single execution */
pthread_key_t __thr_key;                                /* pthread key */
void _thr_onc_init();                                   /* creates pthread key */
void _thr_onc_term(void*);                              /* key destructor function */
#endif

/* these are only used in an out of memory situation... */
static fd_set __g_svc_fdset;
static struct opaque_auth __g_null_auth;
static struct rpc_createerr_t __g_rpc_createerr_t;

/* per-thread global variables encapsulated in one block, makes TLS mgmt easier */
struct __thr_rpc_vars {
    fd_set _svc_fdset;
    struct opaque_auth __null_auth;
    struct rpc_createerr_t _rpc_createerr_t;
};

#ifdef WIN32

DWORD __thr_key;

struct __thr_rpc_vars* _get_thr_rpc_vars()
{
    struct __thr_rpc_vars* ptr = TlsGetValue(__thr_key);

    if (!ptr && (ptr=malloc(sizeof(struct __thr_rpc_vars)))) {
        memset(ptr,0,sizeof(struct __thr_rpc_vars));
        TlsSetValue(__thr_key, ptr);
    }
    else if (!ptr) {
        nt_rpc_report("out of memory");
    }
    return ptr;
}

#else

struct __thr_rpc_vars* _get_thr_rpc_vars()
{
    struct __thr_rpc_vars* ptr = NULL;

    pthread_once(&__thr_onc_control, _thr_onc_init);
    ptr = pthread_getspecific(__thr_key);
    if (!ptr && (ptr=malloc(sizeof(struct __thr_rpc_vars)))) {
        memset(ptr,0,sizeof(struct __thr_rpc_vars));
        pthread_setspecific(__thr_key, ptr);
    }
    else if (!ptr) {
        fprintf(stderr,"_get_thr_rpc_vars: out of memory");
    }
    return ptr;
}

void _thr_onc_init()
{
    pthread_key_create(&__thr_key, _thr_onc_term);
}

void _thr_onc_term(void* ptr)
{
    if (ptr)
        free(ptr);
}

#endif

#if defined(WIN32) && defined(__BORLANDC__)
#define ONC_EXPORT __declspec(dllexport)
#else
#define ONC_EXPORT
#endif

ONC_EXPORT struct opaque_auth* _thr_null_auth(void)
{
    struct __thr_rpc_vars* ptr = _get_thr_rpc_vars();
    return ptr ? &(ptr->__null_auth) : &__g_null_auth;
}

ONC_EXPORT struct rpc_createerr_t* _thr_rpc_createerr(void)
{
    struct __thr_rpc_vars* ptr = _get_thr_rpc_vars();
    return ptr ? &(ptr->_rpc_createerr_t) : &__g_rpc_createerr_t;
}

#ifdef FD_SETSIZE

ONC_EXPORT fd_set* _thr_svc_fdset(void)
{
    struct __thr_rpc_vars* ptr = _get_thr_rpc_vars();
    return ptr ? &(ptr->_svc_fdset) : &__g_svc_fdset;
}

#else

int svc_fds;

#endif /* def FD_SETSIZE */


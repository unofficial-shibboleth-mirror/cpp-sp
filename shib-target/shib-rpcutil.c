/*
 * shib-rpcutil.c -- RPC Utility functions for the SHIB Target
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include <sys/socket.h>

#include "config.h"

#ifdef NEED_RPC_TLI
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif
#endif

#include "shib-target.h"

CLIENT *
shibrpc_client_create (ShibSocket sock, u_long program, u_long version)
{
  struct sockaddr_in sin;

  memset (&sin, 0, sizeof (sin));
  sin.sin_port = 1;

#ifdef NEED_RPC_TLI
  /*
   * there's an undocumented restriction that the fd you pass in
   * needs to support the TLI operations.
   */
  if (ioctl (sock, I_PUSH, "timod") < 0) {
    perror("I_PUSH");
    close (sock);
    return NULL;
  }

  return clnt_tli_create (sock, NULL, NULL, program, version, 0, 0);
#endif

  return clnttcp_create (&sin, program, version, &sock, 0, 0);
}

/*
 * shib-rpcutil.c -- RPC Utility functions for the SHIB Target
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include <sys/socket.h>

#include "shib-target.h"

CLIENT *
shibrpc_client_create (ShibSocket sock, u_long program, u_long version)
{
  struct sockaddr_in sin;

  memset (&sin, 0, sizeof (sin));
  sin.sin_port = 1;

  return clnttcp_create (&sin, program, version, &sock, 0, 0);
}

void
shibrpc_svc_run (ShibSocket listener, const ShibRPCProtocols protos[], int numproto)
{
  SVCXPRT *transp;
  int i;

  /* Wrap an RPC Service around the listener socket */
  transp = svctcp_create (listener, 0, 0);
  if (!transp) {
    fprintf (stderr, "Cannot create RPC Listener\n");
    return;
  }

  /* Register the SHIBRPC RPC Program */
  for (i = 0; i < numproto; i++) {
    if (!svc_register (transp, protos[i].prog, protos[i].vers,
		       protos[i].dispatch, 0)) {
      fprintf (stderr, "Cannot register RPC Program\n");
      return;
    }
  }

  /* Run RPC */
  svc_run ();			/* Never Returns */
}

/*
 * shar.c -- the SHAR "main" code.  All the functionality is elsewhere
 *           (in case you want to turn this into a library later).
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include <unistd.h>
#include <stdio.h>

#include "shib-target.h"

extern void shibrpc_prog_1(struct svc_req *, SVCXPRT *);

int
main (int argc, char *argv[])
{
  ShibSocket sock;
  SVCXPRT *transp;
  char* config = getenv("SHIBCONFIG");

  /* initialize the shib-target library */
  if (shib_target_initialize(SHIBTARGET_SHAR, config))
    return -1;

  /* Create the SHAR listener socket */
  if (shib_sock_create (&sock) != 0)
    return -2;

  /* Bind to the proper port */
  if (shib_sock_bind (sock, SHIB_SHAR_SOCKET) != 0)
    return -3;

  /* Wrap an RPC Service around the listener socket */
  transp = svctcp_create (sock, 0, 0);
  if (!transp) {
    fprintf (stderr, "Cannot create RPC Listener\n");
    return -4;
  }

  /* Register the SHIBRPC RPC Program */
  if (!svc_register (transp, SHIBRPC_PROG, SHIBRPC_VERS_1, shibrpc_prog_1, 0)) {
    fprintf (stderr, "Cannot register RPC Program\n");
    return -5;
  }

  /* Run RPC */
  svc_run ();			/* Never Returns */
  fprintf (stderr, "svc_run returned.\n");
  return 0;

  /* XXX: the user may have to remove the SHAR Socket */
}

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

#include <shib-target/shib-target.h>

extern void shibrpc_prog_1(struct svc_req *, SVCXPRT *);

int
main (int argc, char *argv[])
{
  ShibSocket sock;
  char* config = getenv("SHIBCONFIG");
  ShibRPCProtocols protos[] = {
    { SHIBRPC_PROG, SHIBRPC_VERS_1, shibrpc_prog_1 }
  };

  /* initialize the shib-target library */
  if (shib_target_initialize(SHIBTARGET_SHAR, config))
    return -1;

  /* Create the SHAR listener socket */
  if (shib_sock_create (&sock) != 0)
    return -2;

  /* Bind to the proper port */
  if (shib_sock_bind (sock, SHIB_SHAR_SOCKET) != 0)
    return -3;

  shibrpc_svc_run(sock, protos, 1);

  shib_sock_close(sock);
  fprintf (stderr, "svc_run returned.\n");
  return 0;

  /* XXX: the user may have to remove the SHAR Socket */
}

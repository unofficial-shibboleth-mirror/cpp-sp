/*
 * shib-rpcutil.c -- RPC Utility functions for the SHIB Target
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include <sys/socket.h>

#include "config.h"

#include "shib-target.h"

CLIENT *
shibrpc_client_create (ShibSocket sock, u_long program, u_long version)
{
  struct sockaddr_in sin;

  memset (&sin, 0, sizeof (sin));
  sin.sin_port = 1;

  return clnttcp_create (&sin, program, version, &sock, 0, 0);
}

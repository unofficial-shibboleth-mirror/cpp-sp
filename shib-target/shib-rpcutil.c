/*
 * shib-rpcutil.c -- RPC Utility functions for the SHIB Target
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#ifdef WIN32
# include <winsock.h>
#else
# include <sys/socket.h>
#endif

// eventually we might be able to support autoconf via cygwin...
#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#include "shib-target.h"

CLIENT *
shibrpc_client_create (ShibSocket sock, u_long program, u_long version)
{
  struct sockaddr_in sin;

  memset (&sin, 0, sizeof (sin));
  sin.sin_port = 1;

  return clnttcp_create (&sin, program, version, &sock, 0, 0);
}

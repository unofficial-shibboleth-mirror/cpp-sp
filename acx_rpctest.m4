AC_DEFUN([ACX_RPCTEST], [

AC_LANG_SAVE
AC_LANG_C

AC_REQUIRE([AC_CANONICAL_HOST])

old_LIBS="$LIBS"
AC_SEARCH_LIBS(svcfd_create,nsl,,)
AC_SEARCH_LIBS(socket,socket,,)

AC_TRY_RUN([
/*
 * test-svc-fd -- see if we can use svc_fd
 */

#include <unistd.h>
#include <stdio.h>
#include <sys/select.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#ifdef NEED_RPC_TLI
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif
#endif

#include <rpc/rpc.h>
typedef int ShibSocket;

#ifdef USE_AF_INET
typedef unsigned short ShibSockName;
#define SHIB_SHAR_SOCKET 12345
#else
typedef char* ShibSockName;
#define SHIB_SHAR_SOCKET "/tmp/testing-socket"
#endif

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 100
#endif

#ifdef NEED_SVCFD_CREATE_DEFN
extern SVCXPRT* svcfd_create ();
#endif

/* Create a ShibSocket -- return 0 on success; non-zero on error */
static int
shib_sock_create (ShibSocket *sock)
{
  if (!sock) return EINVAL;

  *sock = socket (
#ifdef USE_AF_INET
		  PF_INET,
#else
		  PF_UNIX,
#endif
		  SOCK_STREAM, 0);
  if (*sock < 0) {
    perror ("socket");
    return EINVAL;
  }
    
  return 0;
}

/* Bind the socket to the name. 
 *
 * NOTE: This will close the socket on failure 
 */
static int
shib_sock_bind (ShibSocket s, ShibSockName name)
{
#ifdef USE_AF_INET
  struct sockaddr_in sunaddr;

  memset (&sunaddr, 0, sizeof (sunaddr));
  sunaddr.sin_family = AF_INET;
  sunaddr.sin_addr.s_addr = INADDR_LOOPBACK;
  sunaddr.sin_port = name;

#else
  struct sockaddr_un sunaddr;

  memset (&sunaddr, 0, sizeof (sunaddr));
  sunaddr.sun_family = AF_UNIX;
  strncpy (sunaddr.sun_path, name, UNIX_PATH_MAX);
#endif

  if (bind (s, (struct sockaddr *)&sunaddr, sizeof (sunaddr)) < 0) {
    perror ("bind");
    close (s);
    return EINVAL;
  }

  /* Make sure that only the creator can read -- we don't want just
   * anyone connecting, do we?
   */
#ifndef USE_AF_INET
  if (chmod (name, 0777) < 0) {
    perror("chmod");
    close (s);
    unlink (name);
    return EINVAL;
  }
#endif

  listen (s, 3);

  return 0;
}

static int
test_svc_create (ShibSocket sock)
{
  int i;
  SVCXPRT *svc;

#if NEED_RPC_TLI
  /*
   * there's an undocumented restriction that the fd you pass in
   * needs to support the TLI operations.
   */
  if (ioctl (sock, I_PUSH, "timod") < 0) {
    perror("I_PUSH");
    close (sock);
    return -1;
  }
#endif

  /* Wrap an RPC Service around the new connection socket */
  svc = svcfd_create (sock, 0, 0);
  if (!svc) {
    perror("svc_fd_create");
    fprintf (stderr, "Cannot create RPC Listener\n");
    return -2;
  }

  return 0;
}

int
main (int argc, char *argv[])
{
  ShibSocket sock;
  int retval;

  /* Create the SHAR listener socket */
  if (shib_sock_create (&sock) != 0)
    exit(-3);

  /* Bind to the proper port */
  if (shib_sock_bind (sock, SHIB_SHAR_SOCKET) != 0)
    exit(-4);

  retval = test_svc_create (sock);
#ifndef USE_AF_INET  
  unlink (SHIB_SHAR_SOCKET);
#endif
  exit(retval);
}],
[$1],
[$2]
)

LIBS="$old_LIBS"

AC_LANG_RESTORE

])


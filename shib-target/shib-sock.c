/*
 * shib-sock.c -- common "socket" routines for the SHIRE/RM and SHAR
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#ifndef HAVE_UNISTD_H
# include <winsock.h>
#else
# include <sys/socket.h>
# include <sys/un.h>
# include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>		/* for chmod() */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#ifdef WIN32
# define SHIBTARGET_EXPORTS __declspec(dllexport)
#endif

#include "shib-target.h"

#ifdef WIN32

typedef struct sockaddr_in SHIBADDR;

// called when there was definitly an error
// return the winsock errno to use as a unix errno
// but make sure it is >=1 so failures stay failures
static int get_winsock_errno(void)
{
  int rc=WSAGetLastError();
  if(rc<=0)
    rc=1;
  return rc;
}

// map a winsock call result to:
// 0-success
// else a unix errno
static int map_winsock_result(int rc)
{
 if(rc!=SOCKET_ERROR)
  return 0;
 return get_winsock_errno();
}

int
shib_sock_create (ShibSocket *sock)
{
  int rc=socket(AF_INET,SOCK_STREAM,0);
  if(rc==SOCKET_ERROR)
    return get_winsock_errno();
  return rc;
}

static void setup_sockaddr(SHIBADDR *addr, short aport)
{
  const char *LOOPBACK_IP="127.0.0.1";
  memset(addr,0,sizeof(SHIBADDR));
  addr->sin_family=AF_INET;
  addr->sin_port=htons(aport);
  addr->sin_addr.s_addr=inet_addr(LOOPBACK_IP);
}

int
shib_sock_bind (ShibSocket s, ShibSockName name)
{
  SHIBADDR addr;
  setup_sockaddr(&addr,name);
  return map_winsock_result(bind(s,(struct sockaddr *)&addr,sizeof(addr)));
}

int
shib_sock_connect (ShibSocket s, ShibSockName name)
{
  SHIBADDR addr;
  setup_sockaddr(&addr,name);
  return map_winsock_result(connect(s,(struct sockaddr *)&addr,sizeof(addr)));
}

void
shib_sock_close (ShibSocket s, ShibSockName name)
{
  int rc=map_winsock_result(closesocket(s));
}

int shib_sock_accept (ShibSocket listener, ShibSocket* s)
{
  int rc;
  if (!s) return EINVAL;
  rc=accept(listener,NULL,NULL);
  if(rc==INVALID_SOCKET)
    return get_winsock_errno();
  *s=rc;
  return 0;
}

/* XXX */

#else /* !WIN32 (== UNIX) */

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 100
#endif

/* Create a ShibSocket -- return 0 on success; non-zero on error */
int
shib_sock_create (ShibSocket *sock)
{
  if (!sock) return EINVAL;

  *sock = socket (PF_UNIX, SOCK_STREAM, 0);
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
int
shib_sock_bind (ShibSocket s, ShibSockName name)
{
  struct sockaddr_un sunaddr;

  memset (&sunaddr, 0, sizeof (sunaddr));
  sunaddr.sun_family = AF_UNIX;
  strncpy (sunaddr.sun_path, name, UNIX_PATH_MAX);

  if (bind (s, (struct sockaddr *)&sunaddr, sizeof (sunaddr)) < 0) {
    perror ("bind");
    close (s);
    return EINVAL;
  }

  /* Make sure that only the creator can read -- we don't want just
   * anyone connecting, do we?
   */
  if (chmod (name, 0777) < 0) {
    perror("chmod");
    close (s);
    unlink (name);
    return EINVAL;
  }

  listen (s, 3);

  return 0;
}

/* Connect the socket to the local host and "port name" */
int
shib_sock_connect (ShibSocket s, ShibSockName name)
{
  struct sockaddr_un sunaddr;

  memset (&sunaddr, 0, sizeof (sunaddr));
  sunaddr.sun_family = AF_UNIX;
  strncpy (sunaddr.sun_path, name, UNIX_PATH_MAX);

  if (connect (s, (struct sockaddr *)&sunaddr, sizeof (sunaddr)) < 0) {
    perror ("connect");
    return 1;
  }

  return 0;
}

/* close the socket (and remove the file) */
void
shib_sock_close (ShibSocket s, ShibSockName name)
{
  if (name) {
    if (unlink (name))
      perror ("unlink");
  }
  close (s);
}

int shib_sock_accept (ShibSocket listener, ShibSocket* s)
{
  if (!s) return EINVAL;

  *s = accept (listener, NULL, NULL);
  if (*s < 0)
    return errno;

  return 0;
}


#endif /* WIN32 */

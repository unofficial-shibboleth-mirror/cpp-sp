/*
 * shib-sock.c -- common "socket" routines for the SHIRE/RM and SHAR
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>		/* for chmod() */
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "shib-target.h"

#ifdef WIN32

#error "Need to define functions for Win32"

int
shib_sock_create (ShibSocket *sock)
{
}

int
shib_sock_bind (ShibSocket s, ShibSockName name)
{
}

int
shib_sock_connect (ShibSocket s, ShibSockName name)
{
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

#endif /* WIN32 */

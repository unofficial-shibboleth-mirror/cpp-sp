/*
 * The Shibboleth License, Version 1.
 * Copyright (c) 2002
 * University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution, if any, must include
 * the following acknowledgment: "This product includes software developed by
 * the University Corporation for Advanced Internet Development
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement
 * may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear.
 *
 * Neither the name of Shibboleth nor the names of its contributors, nor
 * Internet2, nor the University Corporation for Advanced Internet Development,
 * Inc., nor UCAID may be used to endorse or promote products derived from this
 * software without specific prior written permission. For written permission,
 * please contact shibboleth@shibboleth.org
 *
 * Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor
 * may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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

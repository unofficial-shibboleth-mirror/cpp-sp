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

#include "internal.h"

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

#if defined(WANT_TCP_SHAR)
static void setup_tcp_sockaddr(struct sockaddr_in *addr, ShibSockName name)
{
    // Split on host:port boundary. Default to port only.
    char* dup=strdup(name);
    char* port=strchr(dup,':');
    if (port)
        *(port++)=0;
    
    memset(addr,0,sizeof(struct sockaddr_in));
    addr->sin_family=AF_INET;
    addr->sin_port=htons((unsigned short)atoi(port ? port : dup));
    addr->sin_addr.s_addr=inet_addr(port ? dup : "127.0.0.1");
    
    free(dup);
}
#endif

#ifdef WIN32

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

int shib_sock_create(ShibSocket *sock)
{
    *sock=socket(AF_INET,SOCK_STREAM,0);
    if(*sock==INVALID_SOCKET)
        return get_winsock_errno();
    return 0;
}

int shib_sock_bind(ShibSocket s, ShibSockName name)
{
  struct sockaddr_in addr;
  int res;

  setup_tcp_sockaddr(&addr,name);
  res = map_winsock_result(bind(s,(struct sockaddr *)&addr,sizeof(addr)));
  if (res)
      return res;
  return map_winsock_result(listen(s,3));
}

int shib_sock_connect(ShibSocket s, ShibSockName name)
{
  struct sockaddr_in addr;
  setup_tcp_sockaddr(&addr,name);
  return map_winsock_result(connect(s,(struct sockaddr *)&addr,sizeof(addr)));
}

void shib_sock_close(ShibSocket s, ShibSockName name)
{
  int rc=map_winsock_result(closesocket(s));
}

int shib_sock_accept(ShibSocket listener, ShibSocket* s)
{
  unsigned int index=0;
  ShibSockName acl,client;
  struct sockaddr_in addr;
  size_t size=sizeof(addr);

  if (!s) return EINVAL;
  *s=accept(listener,(struct sockaddr*)&addr,&size);
  if(*s==INVALID_SOCKET)
    return get_winsock_errno();
  client=inet_ntoa(addr.sin_addr);
  while ((acl=shib_target_sockacl(index++))!=(ShibSockName)0)
  {
    if (!strcmp(acl,client))
        return 0;
  }
  shib_sock_close(*s,(ShibSockName)0);
  *s=-1;
  fprintf(stderr,"shib_sock_accept(): rejected client at %s\n",client);
  return EACCES;
}

#else /* !WIN32 (== UNIX) */

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 100
#endif

/* Create a ShibSocket -- return 0 on success; non-zero on error */
int shib_sock_create(ShibSocket *sock)
{
  if (!sock) return EINVAL;

#ifdef WANT_TCP_SHAR
  *sock = socket (PF_INET, SOCK_STREAM, 0);
#else
  *sock = socket (PF_UNIX, SOCK_STREAM, 0);
#endif
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
int shib_sock_bind(ShibSocket s, ShibSockName name)
{
#ifdef WANT_TCP_SHAR
  struct sockaddr_in addr;
  
  setup_tcp_sockaddr(&addr,name);
#else
  struct sockaddr_un addr;

  memset (&addr, 0, sizeof (addr));
  addr.sun_family = AF_UNIX;
  strncpy (addr.sun_path, name, UNIX_PATH_MAX);
#endif

  if (bind (s, (struct sockaddr *)&addr, sizeof (addr)) < 0) {
    perror ("bind");
    close (s);
    return EINVAL;
  }

#ifndef WANT_TCP_SHAR
  /* Make sure that only the creator can read -- we don't want just
   * anyone connecting, do we?
   */
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

/* Connect the socket to the local host and "port name" */
int shib_sock_connect(ShibSocket s, ShibSockName name)
{
#ifdef WANT_TCP_SHAR
  struct sockaddr_in addr;
  
  setup_tcp_sockaddr(&addr,name);
#else
  struct sockaddr_un addr;

  memset (&addr, 0, sizeof (addr));
  addr.sun_family = AF_UNIX;
  strncpy (addr.sun_path, name, UNIX_PATH_MAX);
#endif

  if (connect (s, (struct sockaddr *)&addr, sizeof (addr)) < 0) {
    perror ("connect");
    return 1;
  }

  return 0;
}

/* close the socket (and remove the file) */
void shib_sock_close(ShibSocket s, ShibSockName name)
{
#ifndef WANT_TCP_SHAR
  if (name) {
    if (unlink (name))
      perror ("unlink");
  }
#endif
  close (s);
}

int shib_sock_accept(ShibSocket listener, ShibSocket* s)
{
#ifdef WANT_TCP_SHAR
  unsigned int index=0;
  ShibSockName acl,client;
  struct sockaddr_in addr;
  size_t size=sizeof(addr);

  if (!s) return EINVAL;
  *s=accept(listener,(struct sockaddr*)&addr,&size);
  if (*s < 0)
    return errno;
  client=inet_ntoa(addr.sin_addr);
  while ((acl=shib_target_sockacl(index++))!=(ShibSockName)0)
  {
    if (!strcmp(acl,client))
        return 0;
  }
  shib_sock_close(*s,(ShibSockName)0);
  *s=-1;
  fprintf(stderr,"shib_sock_accept(): rejected client at %s\n",client);
  return EACCES;
#else
  if (!s) return EINVAL;
  *s=accept(listener,NULL,NULL);
  if (*s < 0)
    return errno;
  return 0;
#endif
}


#endif /* WIN32 */

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
 * shar.c -- the SHAR "main" code.  All the functionality is elsewhere
 *           (in case you want to turn this into a library later).
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

// eventually we might be able to support autoconf via cygwin...
#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#include <sys/select.h>
#endif

#ifdef WIN32
int getdtablesize()
{
    return 0;
}
#endif

#include <stdio.h>
#include <errno.h>
#include <signal.h>

#include "shar-utils.h"

void shibrpc_prog_1(struct svc_req *rqstp, register SVCXPRT *transp);

#ifdef NEED_SVCFD_CREATE_DEFN
extern SVCXPRT* svcfd_create ();
#endif

static int shar_run = 1;
#if 0
static int foreground = 0;
#endif

int shar_create_svc(ShibSocket sock, const ShibRPCProtocols protos[], int numprotos)
{
  int i;
  SVCXPRT *svc;

  /* Wrap an RPC Service around the new connection socket */
#ifdef WIN32
  svc = svctcp_create(sock, 0, 0);
#else
  svc = svcfd_create (sock, 0, 0);
#endif
  if (!svc) {
    fprintf (stderr, "Cannot create RPC Listener\n");
    return -1;
  }

  /* Register the SHIBRPC RPC Program */
  for (i = 0; i < numprotos; i++) {
    if (!svc_register (svc, protos[i].prog, protos[i].vers,
		       protos[i].dispatch, 0)) {
      svc_destroy(svc);
#ifdef WIN32
      closesocket(sock);
#else
      close(sock);
#endif
      fprintf (stderr, "Cannot register RPC Program\n");
      return -2;
    }
  }
  return 0;
}

static int new_connection(ShibSocket listener, const ShibRPCProtocols protos[], int numproto)
{
  ShibSocket sock;

  /* Accept the connection */
  if (shib_sock_accept(listener, &sock)) {
    fprintf(stderr, "ACCEPT failed\n");
    return -1;
  }

  shar_new_connection(sock, protos, numproto);
  return 0;
}

static void shar_svc_run(ShibSocket listener, const ShibRPCProtocols protos[], int numproto)
{
  fd_set readfds;
  struct timeval tv = { 0, 0 };

  while (shar_run) {
    FD_ZERO(&readfds);
    FD_SET(listener, &readfds);
    tv.tv_sec = 5;

    switch (select (getdtablesize(), &readfds, 0, 0, &tv)) {

    case -1:
      if (errno == EINTR) continue;
      perror("shar_svc_run: - select failed");
      return;

    case 0:
      continue;

    default:
      new_connection(listener, protos, numproto);
    }
  }
}

#ifdef WIN32

static BOOL term_handler(DWORD dwCtrlType)
{
  shar_run = 0;
  return TRUE;
}

#else

static void term_handler(int arg)
{
  shar_run = 0;
}

#endif

static int setup_signals(void)
{
#ifdef WIN32
  SetConsoleCtrlHandler((PHANDLER_ROUTINE)term_handler,TRUE);
#else
  struct sigaction sa;

  memset(&sa, 0, sizeof (sa));
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = SA_RESTART;

  if (sigaction(SIGPIPE, &sa, NULL) < 0) {
    perror ("sigaction SIGPIPE");
    return -1;
  }

  memset(&sa, 0, sizeof (sa));
  sa.sa_handler = term_handler;
  sa.sa_flags = SA_RESTART;

  if (sigaction(SIGHUP, &sa, NULL) < 0) {
    perror ("sigaction SIGHUP");
    return -1;
  }
  if (sigaction(SIGINT, &sa, NULL) < 0) {
    perror ("sigaction SIGINT");
    return -1;
  }
  if (sigaction(SIGQUIT, &sa, NULL) < 0) {
    perror ("sigaction SIGQUIT");
    return -1;
  }
  if (sigaction(SIGTERM, &sa, NULL) < 0) {
    perror ("sigaction SIGTERM");
    return -1;
  }
#endif
  return 0;
}

static void usage(char* whoami)
{
  fprintf (stderr, "usage: %s [-f]\n", whoami);
  fprintf (stderr, "  -f\tforce removal of listener socket\n");
#if 0
  fprintf (stderr, "  -F\trun in the foreground.\n");
#endif
  fprintf (stderr, "  -h\tprint this help message.\n");
  exit (1);
}

static int parse_args(int argc, char* argv[])
{
#ifndef WIN32
  int opt;

  while ((opt = getopt(argc, argv, "fFh")) > 0) {
    switch (opt) {
    case 'f':
      /* XXX: I know that this is a string on Unix */
      unlink (shib_target_sockname());
      break;
#if 0
    case 'F':
      foreground++;
      break;
#endif
    default:
      return -1;
    }
  }
#endif
  return 0;
}

int main (int argc, char *argv[])
{
  ShibSocket sock;
  char* config = getenv("SHIBCONFIG");
  ShibRPCProtocols protos[] = {
    { SHIBRPC_PROG, SHIBRPC_VERS_1, shibrpc_prog_1 }
  };

  if (setup_signals() != 0)
    return -1;

  if (parse_args(argc, argv) != 0)
    usage(argv[0]);

  /* initialize the shib-target library */
  if (shib_target_initialize(SHIBTARGET_SHAR, config))
    return -2;

  /* Create the SHAR listener socket */
  if (shib_sock_create(&sock) != 0)
    return -3;

  /* Bind to the proper port */
  if (shib_sock_bind(sock, shib_target_sockname()) != 0)
    return -4;

#if 0
#ifndef WIN32
  /* (maybe) Put myself into the background. */
  if (!foreground)
    daemon(0, 1);		/* chdir to /, but do not redirect stdout/stderr */
#endif
#endif

  /* Initialize the SHAR Utilitites */
  shar_utils_init();

  /* Run the listener */
  shar_svc_run(sock, protos, 1);

  /* Finalize the SHAR, close all clients */
  shar_utils_fini();

  shib_sock_close(sock, shib_target_sockname());
  fprintf(stderr, "shar_svc_run returned.\n");
  return 0;
}

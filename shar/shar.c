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
#include <sys/select.h>
#include <errno.h>
#include <signal.h>

#include "config.h"

#include <shib-target/shib-target.h>

typedef struct {
  u_long prog;
  u_long vers;
  void (*dispatch)();
} ShibRPCProtocols;

#ifdef NEED_SVCFD_CREATE_DEFN
extern SVCXPRT* svcfd_create ();
#endif

extern void shibrpc_prog_1(struct svc_req *, SVCXPRT *);
static int shar_run = 1;

static int
new_connection (ShibSocket listener, const ShibRPCProtocols protos[], int numproto)
{
  int i;
  SVCXPRT *svc;
  ShibSocket sock;

  /* Accept the connection */
  if (shib_sock_accept (listener, &sock)) {
    fprintf (stderr, "ACCEPT failed\n");
    return -1;
  }

  /* Wrap an RPC Service around the new connection socket */
  svc = svcfd_create (sock, 0, 0);
  if (!svc) {
    fprintf (stderr, "Cannot create RPC Listener\n");
    return -2;
  }

  /* Register the SHIBRPC RPC Program */
  for (i = 0; i < numproto; i++) {
    if (!svc_register (svc, protos[i].prog, protos[i].vers,
		       protos[i].dispatch, 0)) {
      svc_destroy(svc);
      close (sock);
      fprintf (stderr, "Cannot register RPC Program\n");
      return -3;
    }
  }
  return 0;
}

static void
shar_svc_run (ShibSocket listener, const ShibRPCProtocols protos[], int numproto)
{
  while (shar_run) {
    fd_set readfds = svc_fdset;
    struct timeval tv = { 0, 0 };

    FD_SET(listener, &readfds);
    tv.tv_sec = 5;

    switch (select (getdtablesize(), &readfds, 0, 0, &tv)) {

    case -1:
      if (errno == EINTR) continue;
      perror ("shar_svc_run: - select failed");
      return;

    case 0:
      continue;

    default:
      if (FD_ISSET (listener, &readfds)) {
	new_connection (listener, protos, numproto);
	FD_CLR (listener, &readfds);
      }

      svc_getreqset (&readfds);
    }
  }
}

static void term_handler (int arg)
{
  shar_run = 0;
}

static int setup_signals (void)
{
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

  return 0;
}

static void usage(char* whoami)
{
  fprintf (stderr, "usage: %s [-f]\n", whoami);
  fprintf (stderr, "  -f\tforce removal of listener socket\n");
  exit (1);
}

static int parse_args(int argc, char* argv[])
{
  int opt;

  while ((opt = getopt(argc, argv, "fh")) > 0) {
    switch (opt) {
    case 'f':
#ifndef WIN32
      /* XXX: I know that this is a string on Unix */
      unlink (SHIB_SHAR_SOCKET);
#endif
      break;
    default:
      return -1;
    }
  }
  return 0;
}

int
main (int argc, char *argv[])
{
  ShibSocket sock;
  char* config = getenv("SHIBCONFIG");
  ShibRPCProtocols protos[] = {
    { SHIBRPC_PROG, SHIBRPC_VERS_1, shibrpc_prog_1 }
  };

  if (parse_args (argc, argv) != 0)
    usage(argv[0]);

  if (setup_signals() != 0)
    return -1;

  /* initialize the shib-target library */
  if (shib_target_initialize(SHIBTARGET_SHAR, config))
    return -2;

  /* Create the SHAR listener socket */
  if (shib_sock_create (&sock) != 0)
    return -3;

  /* Bind to the proper port */
  if (shib_sock_bind (sock, SHIB_SHAR_SOCKET) != 0)
    return -4;

  shar_svc_run(sock, protos, 1);

  shib_sock_close(sock, SHIB_SHAR_SOCKET);
  fprintf (stderr, "shar_svc_run returned.\n");
  return 0;
}

#include <unistd.h>
#include <stdio.h>

#include "shib-target.h"

int
main (int argc, char *argv[])
{
  int sock, res;
  CLIENT *clnt;
  enum clnt_stat clnt_stat;

  if (shib_sock_create (&sock) != 0)
    return -1;

  if (shib_sock_connect (sock, SHIB_SHAR_SOCKET) != 0)
    return -2;

  clnt = shibrpc_client_create (sock, SHIBRPC_PROG, SHIBRPC_VERS_1);
  if (!clnt) {
    clnt_pcreateerror ("shibrpc_client_create");
    return -3;
  }

  res = 0;
  clnt_stat = shibrpc_ping_1 (&sock, &res, clnt);

  if (clnt_stat != RPC_SUCCESS) {
    clnt_perror (clnt, "rpc");
    return -4;
  }

  printf("%d -> %d\n", sock, res);
  clnt_destroy (clnt);

  return 0;
}

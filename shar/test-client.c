#include <stdio.h>
#include <shib-target/shib-target.h>

int main (int argc, char *argv[])
{
  ShibSocket sock;
  int res,start;
  CLIENT *clnt;
  enum clnt_stat clnt_stat;

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
  WORD wVersionRequested;  
  WSADATA wsaData; 
  int err; 
  wVersionRequested = MAKEWORD(1, 0); 
    
  err = WSAStartup(wVersionRequested, &wsaData);
#endif

  if ((res=shib_sock_create(&sock)) != 0)
  {
    printf("shib_sock_create failed: %d\n",res);
    return -1;
  }

  if ((res=shib_sock_connect(sock, SHIB_SHAR_SOCKET)) != 0)
  {
    printf("shib_sock_connect failed: %d\n",res);
    return -2;
  }

  clnt = shibrpc_client_create(sock, SHIBRPC_PROG, SHIBRPC_VERS_1);
  if (!clnt) {
    clnt_pcreateerror ("shibrpc_client_create");
    printf("shibrpc_client_create failed\n");
    return -3;
  }

  res = start = 0;
  clnt_stat = shibrpc_ping_1 (&start, &res, clnt);

  if (clnt_stat != RPC_SUCCESS) {
    clnt_perror (clnt, "rpc");
    printf("RPC error: %d, %d\n",clnt_stat,res);
    return -4;
  }

  printf("%d -> %d\n", sock, res);
  clnt_destroy (clnt);

  return 0;
}

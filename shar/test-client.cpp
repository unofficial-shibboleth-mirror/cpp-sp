#include <shib-target/shib-target.h>
#include <iostream>

using namespace std;
using namespace shibtarget;

int main (int argc, char *argv[])
{
  int res,start;
  enum clnt_stat clnt_stat;

  const char* config=getenv("SHIBCONFIG");
  if (!config)
    config=SHIB_CONFIG;
  const char* schemadir=getenv("SHIBSCHEMAS");
  if (!schemadir)
    schemadir=SHIB_SCHEMAS;

  ShibTargetConfig& conf=ShibTargetConfig::getConfig();
  conf.setFeatures(ShibTargetConfig::Listener);
  if (!conf.init(schemadir,config))
      return -10;

  IListener::ShibSocket sock;
  const IListener* listener=conf.getINI()->getListener();
  if (!listener->create(sock))
  {
    cerr << "create failed\n";
    return -1;
  }

  if (!listener->connect(sock))
  {
    cerr << "connect failed\n";
    return -2;
  }

  CLIENT* clnt = listener->getClientHandle(sock,SHIBRPC_PROG, SHIBRPC_VERS_2);
  if (!clnt) {
    clnt_pcreateerror("shibrpc_client_create");
    cerr << "shibrpc_client_create failed\n";
    return -3;
  }

  res = start = 0;
  clnt_stat = shibrpc_ping_2 (&start, &res, clnt);

  if (clnt_stat != RPC_SUCCESS) {
    clnt_perror (clnt, "rpc");
    cerr << "RPC error:" << clnt_stat << ", " << res << "\n";
    return -4;
  }

  cout << sock << " -> " << res << "\n";
  clnt_destroy (clnt);

  conf.shutdown();
  return 0;
}

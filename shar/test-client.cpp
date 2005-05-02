#include <shib-target/shib-target.h>
#include <iostream>

using namespace std;
using namespace saml;
using namespace shibtarget;

int main (int argc, char *argv[])
{
  const char* config=getenv("SHIBCONFIG");
  if (!config)
    config=SHIB_CONFIG;
  const char* schemadir=getenv("SHIBSCHEMAS");
  if (!schemadir)
    schemadir=SHIB_SCHEMAS;

  ShibTargetConfig& conf=ShibTargetConfig::getConfig();
  conf.setFeatures(ShibTargetConfig::Listener);
  if (!conf.init(schemadir) || !conf.load(config))
      return -10;

  try {
      int i=0;
      conf.getINI()->getListener()->ping(i);
      cerr << 0 << " -> " << i << "\n";
  }
  catch (SAMLException& e) {
      cerr << "caught SAML exception: " << e.what() << "\n";
  }
  
  conf.shutdown();
  return 0;
}

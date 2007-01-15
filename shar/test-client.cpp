/*
 *  Copyright 2001-2005 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <shib-target/shib-target.h>
#include <shibsp/SPConfig.h>
#include <iostream>

using namespace shibsp;
using namespace shibtarget;
using namespace saml;
using namespace xmltooling;
using namespace std;

int main (int argc, char *argv[])
{
    if (argc<=1) {
        cerr << "usage: testclient <integer>" << endl;
        return -1;
    }
  const char* config=getenv("SHIBCONFIG");
  if (!config)
    config=SHIB_CONFIG;
  const char* schemadir=getenv("SHIBSCHEMAS");
  if (!schemadir)
    schemadir=SHIB_SCHEMAS;

  ShibTargetConfig& conf=ShibTargetConfig::getConfig();
  SPConfig::getConfig().setFeatures(SPConfig::Listener | SPConfig::InProcess);
  if (!conf.init(schemadir) || !conf.load(config))
      return -10;

  try {
      DDF in("ping");
      DDFJanitor injan(in);
      in.integer(atol(argv[1]));

      DDF out=SPConfig::getConfig().getServiceProvider()->getListenerService()->send(in);
      DDFJanitor outjan(out);

      cerr << argv[1] << " -> " << out.integer() << "\n";
  }
  catch (exception& e) {
      cerr << "caught exception: " << e.what() << "\n";
  }
  
  conf.shutdown();
  return 0;
}

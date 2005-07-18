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

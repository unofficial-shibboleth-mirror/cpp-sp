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

#include "../shib-target/shib-target.h"
#include "../shib-target/shib-paths.h"

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

ShibTargetConfig* g_Config = NULL;

void shutdown(void)
{
  g_Config->shutdown();
  g_Config = NULL;
}

void init(void)
{
  try {
    g_Config=&ShibTargetConfig::getConfig();
    g_Config->setFeatures(
			  ShibTargetConfig::Listener |
			  ShibTargetConfig::Metadata |
			  ShibTargetConfig::AAP |
			  ShibTargetConfig::RequestMapper |
			  ShibTargetConfig::LocalExtensions
			  );

    if (!g_Config->init(SHIB_SCHEMAS) || !g_Config->load(SHIB_CONFIG)) {
      cerr << "init() failed to initialize SHIB Target" << endl;
      exit(1);
    }
  }
  catch (...) {
    cerr << "init() failed to initialize SHIB Target" << endl;
    exit (1);
  }
}

int main(int argc, char* argv[])
{
  cout << "Running init 1.." << endl;
  init();
  cout << "Running shutdown 1.." << endl;
  shutdown();
  cout << "Running init 2.." << endl;
  init();
  cout << "Running shutdown 2.." << endl;
  shutdown();
  cout << "Done." << endl;
  exit(0);
}

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

#include "shib-target.h"
#include <iostream>
#include <fstream>

using namespace std;
using namespace shibtarget;

main()
{
  ShibMLP mlp;

  mlp.insert("key1", "variable 1");
  mlp.insert("key2", "variable 2");

  string input =
    "This is a test <SHIBMLP key1/> of the emergency <Shibmlp    key2  />"
    " broadcasting system. <ShIbMlP key3 />\n";
    
  cout << mlp.run(input);

  ifstream inf("testmlp.html");
  cout << mlp.run(inf);
}

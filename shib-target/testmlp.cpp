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

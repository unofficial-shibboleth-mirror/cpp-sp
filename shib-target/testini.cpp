#include "shib-target.h"
#include <iostream>

using namespace std;
using namespace shibtarget;

static void test (ShibINI &ini, const char* header)
{
  cout << "Testing Header: \"";
  cout << header;
  cout << "\"\tExists: ";
  cout << (ini.exists (header) ? "Yes\n" : "No\n");
}

static void test (ShibINI &ini, const char* header, const char* tag)
{
  cout << "\t\"";
  cout << header;
  cout << ".";
  cout << tag;
  cout << "\"\tExists: ";
  if (ini.exists (header, tag)) {
    cout << "Yes\tValue: \"";
    cout << ini.get (header, tag);
    cout << "\"\n";
  } else
    cout << "No\n";
}

static void test_header_iter (ShibINI &ini)
{
  cout << "Test Header Iterator: ";
  ShibINI::Iterator* iter = ini.header_iterator();
  for (const string* str = iter->begin(); str; str = iter->next())
    cout << "\"" << *str << "\" ";
  cout << "\n";

  delete iter;
}

static void test_tag_iter (ShibINI &ini, const char* header)
{
  string h = header;
  cout << "Test Tag Iterator \"" << header << "\" : ";
  ShibINI::Iterator* iter = ini.tag_iterator(h);
  for (const string* str = iter->begin(); str; str = iter->next())
    cout << "\"" << *str << "\" ";
  cout << "\n";

  delete iter;
}

static void run_test (ShibINI &ini)
{
  char* headers[] = { "test1", "", "header1", "Header1", "header2", "header2 " };
  char* tags[] = { "test1", "test2", "test3", "test4", "test5", "TeSt5", "test 6" };

  ini.dump(cout);

  test_header_iter (ini);

  for (int i = 0; i < sizeof(headers)/sizeof(*headers); i++) {
    test (ini, headers[i]);

    for (int j = 0; j < sizeof(tags)/sizeof(*tags); j++) 
      test (ini, headers[i], tags[j]);

    test_tag_iter (ini, headers[i]);
  }

}

main()
{
  ShibINI ini("testini.ini");
  run_test (ini);

  ShibINI ini2("testini.ini", false);
  run_test (ini2);
}

#include <log4cpp/Category.hh>
#include <log4cpp/RemoteSyslogAppender.hh>

#include <string>

using namespace std;
using namespace log4cpp;

main()
{
  Category& log = Category::getRoot();

  string name = "name";
  string sysname = "sysname";
  string relayer = "localhost";
  RemoteSyslogAppender app(name, sysname, relayer, -1, -1);
  log.setAppender(app);

  log.error("Test Log Entry");
}

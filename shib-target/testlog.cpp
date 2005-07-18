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

#include <log4cpp/Category.hh>
#include <log4cpp/RemoteSyslogAppender.hh>
#include <log4cpp/SyslogAppender.hh>

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

  Category& syslog = Category::getInstance("test");
  SyslogAppender sapp(name, sysname);
  syslog.setAppender(sapp);

  syslog.error("test Syslog entry");
}

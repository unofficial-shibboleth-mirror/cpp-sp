/*
 * shib-target.cpp -- General target initialization and finalization routines
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#include "shib-target.h"

#include <log4cpp/Category.hh>

using namespace saml;
using namespace shibboleth;
using namespace shibtarget;
using namespace std;

/* shib-target.cpp */

static ShibTargetConfig* g_Config = NULL;

/* initialize and finalize the target library: return 0 on success, 1 on failure */
extern "C" int shib_target_initialize (const char* app_name, const char* inifile)
{
  if (!app_name) {
    cerr << "APPLICATION ERROR: No application supplied to shib_target_init\n";
    return 1;
  }

  if (g_Config) {
    log4cpp::Category& log = log4cpp::Category::getInstance("shibtarget.init");
    log.error("shib_target_initialize: Already initialized");
    return 1;
  }

  try {
    g_Config = &(ShibTargetConfig::init(app_name, inifile));
  } catch (runtime_error &e) {
    return 1;
  }

  return 0;
}

extern "C" void shib_target_finalize (void)
{
  if (!g_Config)
    return;

  g_Config->shutdown();
  g_Config = NULL;
}

/*
 * The Shibboleth License, Version 1.
 * Copyright (c) 2002
 * University Corporation for Advanced Internet Development, Inc.
 * All rights reserved
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution, if any, must include
 * the following acknowledgment: "This product includes software developed by
 * the University Corporation for Advanced Internet Development
 * <http://www.ucaid.edu>Internet2 Project. Alternately, this acknowledegement
 * may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear.
 *
 * Neither the name of Shibboleth nor the names of its contributors, nor
 * Internet2, nor the University Corporation for Advanced Internet Development,
 * Inc., nor UCAID may be used to endorse or promote products derived from this
 * software without specific prior written permission. For written permission,
 * please contact shibboleth@shibboleth.org
 *
 * Products derived from this software may not be called Shibboleth, Internet2,
 * UCAID, or the University Corporation for Advanced Internet Development, nor
 * may Shibboleth appear in their name, without prior written permission of the
 * University Corporation for Advanced Internet Development.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE DISCLAIMED AND THE ENTIRE RISK
 * OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY
 * CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC. BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * shib-target.cpp -- General target initialization and finalization routines
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#ifdef WIN32
# define SHIBTARGET_EXPORTS __declspec(dllexport)
#endif

#include "shib-target.h"

#include <log4cpp/Category.hh>

using namespace saml;
using namespace shibboleth;
using namespace shibtarget;
using namespace std;

/* shib-target.cpp */

namespace {
  ShibTargetConfig* g_Config = NULL;
};

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

  // pre-init the configuration..
  ShibTargetConfig::preinit();

  try {
    g_Config = &(ShibTargetConfig::init(app_name, inifile));
  } catch (runtime_error &e) {
    fprintf(stderr,"shib_target_initialize failed: %s\n",e.what());
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

extern "C" ShibSockName shib_target_sockname(void)
{
    return (g_Config ? g_Config->m_SocketName : (ShibSockName)0);
}

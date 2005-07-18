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

/*
 * shar-utils.h -- header file for the SHAR utilities.
 *
 * Created by:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

#ifndef SHAR_UTILS_H
#define SHAR_UTILS_H

#include <saml/saml.h>
#include <shib-target/shibrpc.h>
#include <shib-target/shib-target.h>

extern "C" {
    typedef void (*dispatch_fn)(struct svc_req* rqstp, register SVCXPRT* transp);
}

struct ShibRPCProtocols
{
    u_long prog;
    u_long vers;
    dispatch_fn dispatch;
};

class SharChild {
public:
    SharChild(shibtarget::IListener::ShibSocket& s, const saml::Iterator<ShibRPCProtocols>& protos);
    ~SharChild();
    void run();

private:
    bool svc_create();
    shibtarget::IListener::ShibSocket sock;
    std::vector<ShibRPCProtocols> v_protos;
    shibboleth::Thread* child;
};

struct SHARUtils
{
    static void init();
    static void fini();
    static void log_error();
};

#endif /* SHAR_UTILS_H */

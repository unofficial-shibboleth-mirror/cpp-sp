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
 * shar.cpp -- the SHAR "main" code.  All the functionality is elsewhere
 *           (in case you want to turn this into a library later).
 *
 * Created By:	Derek Atkins <derek@ihtfp.com>
 *
 * $Id$
 */

// eventually we might be able to support autoconf via cygwin...
#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#include <sys/select.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <signal.h>

#include "shar-utils.h"

using namespace std;
using namespace saml;
using namespace shibboleth;
using namespace shibtarget;

#ifndef FD_SETSIZE
# define FD_SETSIZE 1024
#endif

extern "C" void shibrpc_prog_1(struct svc_req* rqstp, register SVCXPRT* transp);

int shar_run = 1;
const char* config = NULL;
const char* schemadir = NULL;
static int unlink_socket = 0;

static bool new_connection(IListener::ShibSocket& listener, const Iterator<ShibRPCProtocols>& protos)
{
    IListener::ShibSocket sock;

    // Accept the connection.
    if (ShibTargetConfig::getConfig().getINI()->getListener()->accept(listener, sock))
        return false;

    // We throw away the result because the children manage themselves...
    new SharChild(sock,protos);
    return true;
}

static void shar_svc_run(IListener::ShibSocket& listener, const Iterator<ShibRPCProtocols>& protos)
{
    NDC ndc("shar_svc_run");

    while (shar_run) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listener, &readfds);
        struct timeval tv = { 0, 0 };
        tv.tv_sec = 5;
    
        switch (select(FD_SETSIZE, &readfds, 0, 0, &tv)) {
            case -1:
                if (errno == EINTR) continue;
                SHARUtils::log_error();
                return;
        
            case 0:
                continue;
        
            default:
                new_connection(listener, protos);
        }
    }
    printf("shar_svc_run ended\n");
}

#ifdef WIN32

int real_main(int preinit)
{
    static IListener::ShibSocket sock;
    ShibRPCProtocols protos[1] = {
        { SHIBRPC_PROG, SHIBRPC_VERS_1, shibrpc_prog_1 }
    };

    ShibTargetConfig& conf=ShibTargetConfig::getConfig();
    if (preinit) {

        // initialize the shib-target library
        conf.setFeatures(
            ShibTargetConfig::Listener |
            ShibTargetConfig::SessionCache |
            ShibTargetConfig::Metadata |
            ShibTargetConfig::Trust |
            ShibTargetConfig::Credentials |
            ShibTargetConfig::AAP |
            ShibTargetConfig::SHARExtensions
            );
        if (!config)
            config=getenv("SHIBCONFIG");
        if (!schemadir)
            schemadir=getenv("SHIBSCHEMAS");
        if (!conf.init(schemadir,config))
            return -2;

        const IListener* listener=conf.getINI()->getListener();
        
        // Create the SHAR listener socket
        if (!listener->create(sock))
            return -3;

        // Bind to the proper port
        if (!listener->bind(sock))
            return -4;

        // Initialize the SHAR Utilitites
        SHARUtils::init();
    }
    else {
        // Run the listener
        shar_svc_run(sock, ArrayIterator<ShibRPCProtocols>(protos,1));
        fprintf(stderr,"shar_svc_run returned\n");

        // Finalize the SHAR, close all clients
        SHARUtils::fini();
        conf.getINI()->getListener()->close(sock);
        conf.shutdown();
    }
    return 0;
}

#else

static void term_handler(int arg)
{
    shar_run = 0;
}

static int setup_signals(void)
{
    NDC ndc("setup_signals");
    
    struct sigaction sa;
    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGPIPE, &sa, NULL) < 0) {
        SHARUtils::log_error();
        return -1;
    }

    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = term_handler;
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        SHARUtils::log_error();
        return -1;
    }
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        SHARUtils::log_error();
        return -1;
    }
    if (sigaction(SIGQUIT, &sa, NULL) < 0) {
        SHARUtils::log_error();
        return -1;
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        SHARUtils::log_error();
        return -1;
    }
    return 0;
}

static void usage(char* whoami)
{
    fprintf(stderr, "usage: %s [-f]\n", whoami);
    fprintf(stderr, "  -c\tconfig file to use.\n");
    fprintf(stderr, "  -d\tschema directory to use.\n");
    fprintf(stderr, "  -f\tforce removal of listener socket.\n");
    fprintf(stderr, "  -h\tprint this help message.\n");
    exit(1);
}

static int parse_args(int argc, char* argv[])
{
    int opt;

    while ((opt = getopt(argc, argv, "cdfFh")) > 0) {
        switch (opt) {
            case 'c':
                config=optarg;
                break;
            case 'd':
                schemadir=optarg;
                break;
            case 'f':
                unlink_socket = 1;
                break;
            default:
                return -1;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    IListener::ShibSocket sock;
    ShibRPCProtocols protos[] = {
        { SHIBRPC_PROG, SHIBRPC_VERS_1, shibrpc_prog_1 }
    };

    if (setup_signals() != 0)
        return -1;

    if (parse_args(argc, argv) != 0)
        usage(argv[0]);

    if (!schemadir)
        schemadir=getenv("SHIBSCHEMAS");
    if (!config)
        config=getenv("SHIBCONFIG");

    // initialize the shib-target library
    ShibTargetConfig& conf=ShibTargetConfig::getConfig();
    conf.setFeatures(
        ShibTargetConfig::Listener |
        ShibTargetConfig::SessionCache |
        ShibTargetConfig::Metadata |
        ShibTargetConfig::Trust |
        ShibTargetConfig::Credentials |
        ShibTargetConfig::AAP |
        ShibTargetConfig::SHARExtensions
        );
    if (!conf.init(schemadir,config))
        return -2;

    const IListener* listener=conf.getINI()->getListener();
    
    // Create the SHAR listener socket
    if (!listener->create(sock))
        return -3;

    // Bind to the proper port
    if (!listener->bind(sock, unlink_socket==1))
        return -4;

    // Initialize the SHAR Utilitites
    SHARUtils::init();

    // Run the listener
    shar_svc_run(sock, ArrayIterator<ShibRPCProtocols>(protos,1));

    /* Finalize the SHAR, close all clients */
    SHARUtils::fini();
    fprintf(stderr, "shar utils finalized\n");

    listener->close(sock);
    fprintf(stderr, "shib socket closed\n");

    conf.shutdown();
    fprintf(stderr, "shar finished.  bye bye.\n");
    return 0;
}

#endif

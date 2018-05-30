/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

/*
 * shibd.cpp -- the shibd "main" code.
 */


// eventually we might be able to support autoconf via cygwin...
#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <shibsp/SPConfig.h>

#ifdef HAVE_UNISTD_H
# include <unistd.h>
# include <sys/select.h>
#endif

#if defined(HAVE_GRP_H) && defined(HAVE_PWD_H)
# include <pwd.h>
# include <grp.h>
#endif

#include <stdio.h>
#include <signal.h>
#include <shibsp/ServiceProvider.h>
#include <shibsp/remoting/ListenerService.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/XMLConstants.h>
#include <xmltooling/util/XMLHelper.h>

#ifdef HAVE_SD_NOTIFY
#include <systemd/sd-daemon.h>
#else
#define SD_EMERG   ""
#define SD_ALERT   ""
#define SD_CRIT    ""
#define SD_ERR     ""
#define SD_WARNING ""
#define SD_NOTICE  ""
#define SD_INFO    ""
#define SD_DEBUG   ""
#endif

using namespace shibsp;
using namespace xmltooling;
using namespace std;

bool shibd_shutdown = false;
const char* shar_config = nullptr;
const char* shar_schemadir = nullptr;
const char* shar_prefix = nullptr;
bool shar_checkonly = false;
bool shar_version = false;
static bool unlink_socket = false;
const char* pidfile = nullptr;

#ifdef WIN32

//#include <CRTDBG.H>

#define nNoMansLandSize 4
typedef struct _CrtMemBlockHeader
{
        struct _CrtMemBlockHeader * pBlockHeaderNext;
        struct _CrtMemBlockHeader * pBlockHeaderPrev;
        char *                      szFileName;
        int                         nLine;
        size_t                      nDataSize;
        int                         nBlockUse;
        long                        lRequest;
        unsigned char               gap[nNoMansLandSize];
        /* followed by:
         *  unsigned char           data[nDataSize];
         *  unsigned char           anotherGap[nNoMansLandSize];
         */
} _CrtMemBlockHeader;

/*
int MyAllocHook(int nAllocType, void *pvData,
      size_t nSize, int nBlockUse, long lRequest,
      const unsigned char * szFileName, int nLine)
{
    if ( nBlockUse == _CRT_BLOCK )
      return( TRUE );
    if (nAllocType == _HOOK_FREE) {
        _CrtMemBlockHeader* ptr = (_CrtMemBlockHeader*)(((_CrtMemBlockHeader *)pvData)-1);
        if (ptr->nDataSize == 8192)
            fprintf(stderr,"free  request %u size %u\n", ptr->lRequest, ptr->nDataSize);
    }
    else if (nAllocType == _HOOK_ALLOC && nSize == 8192)
        fprintf(stderr,"%s request %u size %u\n", ((nAllocType == _HOOK_ALLOC) ? "alloc" : "realloc"), lRequest, nSize);
    return (TRUE);
}
*/

int real_main(int preinit)
{
    if (shar_version) {
        if (preinit)
            fprintf(stdout, PACKAGE_STRING"\n");
        return 0;
    }

    SPConfig& conf = SPConfig::getConfig();
    if (preinit) {
        // Initialize the SP library.
        conf.setFeatures(
            SPConfig::Listener |
            SPConfig::Caching |
            SPConfig::Metadata |
            SPConfig::Trust |
            SPConfig::Credentials |
            SPConfig::AttributeResolution |
            SPConfig::Handlers |
            SPConfig::OutOfProcess |
            (shar_checkonly ? SPConfig::RequestMapping : SPConfig::Logging)
            );
        if (!conf.init(shar_schemadir, shar_prefix)) {
            fprintf(stderr, "configuration is invalid, see console or log for specific problems\n");
            return -1;
        }

        if (!conf.instantiate(shar_config)) {
            fprintf(stderr, "configuration is invalid, check console or log for specific problems\n");
            conf.term();
            return -2;
        }

        // If just a test run, bail.
        if (shar_checkonly) {
            fprintf(stdout, "overall configuration is loadable, check console or log for non-fatal problems\n");
            return 0;
        }
    }
    else {

        //_CrtSetAllocHook(MyAllocHook);

        if (!shar_checkonly) {
            // Run the listener.
            ListenerService* listener = conf.getServiceProvider()->getListenerService();
            if (!listener->init(unlink_socket)) {
                fprintf(stderr, "listener failed to initialize\n");
                conf.term();
                return -3;
            }
            else if (!listener->run(&shibd_shutdown)) {
                fprintf(stderr, "listener failed during service\n");
                listener->term();
                conf.term();
                return -3;
            }
            listener->term();
        }

        conf.term();
    }
    return 0;
}

#else

int daemon_wait = 3;
bool shibd_running = false;
bool daemonize = true;
const char* runasuser = nullptr;
const char* runasgroup = nullptr;

static void term_handler(int arg)
{
    shibd_shutdown = true;
}

static void run_handler(int arg)
{
    shibd_running = true;
}

static void child_handler(int arg)
{
    // Terminate the parent's wait/sleep if the newly born daemon dies early.
}

static int setup_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGPIPE, &sa, nullptr) < 0) {
        return -1;
    }

    memset(&sa, 0, sizeof (sa));
    sa.sa_handler = term_handler;
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGHUP, &sa, nullptr) < 0) {
        return -1;
    }
    if (sigaction(SIGINT, &sa, nullptr) < 0) {
        return -1;
    }
    if (sigaction(SIGQUIT, &sa, nullptr) < 0) {
        return -1;
    }
    if (sigaction(SIGTERM, &sa, nullptr) < 0) {
        return -1;
    }

    if (daemonize) {
        memset(&sa, 0, sizeof (sa));
        sa.sa_handler = run_handler;

        if (sigaction(SIGUSR1, &sa, nullptr) < 0) {
            return -1;
        }

        memset(&sa, 0, sizeof (sa));
        sa.sa_handler = child_handler;

        if (sigaction(SIGCHLD, &sa, nullptr) < 0) {
            return -1;
        }
    }

    return 0;
}

static void usage(char* whoami)
{
    fprintf(stderr, "usage: %s [-dcxtfFpwugvh]\n", whoami);
    fprintf(stderr, "  -d\tinstallation prefix to use\n");
    fprintf(stderr, "  -c\tconfig file to use\n");
    fprintf(stderr, "  -x\tXML schema catalogs to use\n");
    fprintf(stderr, "  -t\ttest configuration file for problems\n");
    fprintf(stderr, "  -f\tforce removal of listener socket\n");
    fprintf(stderr, "  -F\tstay in the foreground\n");
    fprintf(stderr, "  -p\tpid file to use\n");
    fprintf(stderr, "  -w\tseconds to wait for successful daemonization\n");
    fprintf(stderr, "  -u\tuser to run under\n");
    fprintf(stderr, "  -g\tgroup to run under\n");
    fprintf(stderr, "  -v\tprint software version\n");
    fprintf(stderr, "  -h\tprint this help message\n");
    exit(1);
}

static int parse_args(int argc, char* argv[])
{
    int opt;

    while ((opt = getopt(argc, argv, "d:c:x:p:w:u:g:fFtvh")) > 0) {
        switch (opt) {
            case 'd':
                shar_prefix=optarg;
                break;
            case 'c':
                shar_config=optarg;
                break;
            case 'x':
                shar_schemadir=optarg;
                break;
            case 'f':
                unlink_socket = true;
                break;
            case 'F':
                daemonize = false;
                break;
            case 't':
                shar_checkonly=true;
                daemonize=false;
                break;
            case 'v':
                shar_version=true;
                break;
            case 'p':
                pidfile=optarg;
                break;
            case 'w':
                if (optarg)
                    daemon_wait = atoi(optarg);
                if (daemon_wait <= 0)
                    daemon_wait = 3;
                break;
            case 'u':
                if (optarg)
                    runasuser = optarg;
                break;
            case 'g':
                if (optarg)
                    runasgroup = optarg;
                break;
            default:
                return -1;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (parse_args(argc, argv) != 0)
        usage(argv[0]);
    else if (shar_version) {
        fprintf(stdout, PACKAGE_STRING"\n");
        return 0;
    }

    if (setup_signals() != 0)
        return -1;

    if (runasgroup) {
#ifdef HAVE_GETGRNAM
        struct group* grp = getgrnam(runasgroup);
        if (!grp) {
            fprintf(stderr, "getgrnam failed, check -g option\n");
            return -1;
        }
        if (setgid(grp->gr_gid) != 0) {
            fprintf(stderr, "setgid failed, check -g option\n");
            return -1;
        }
#else
        fprintf(stderr, "-g not supported on this platform");
        return -1;
#endif
    }

    if (runasuser) {
#ifdef HAVE_GETPWNAM
        struct passwd* pwd = getpwnam(runasuser);
        if (!pwd) {
            fprintf(stderr, "getpwnam failed, check -u option\n");
            return -1;
        }
#ifdef HAVE_INITGROUPS
        // w/out initgroups/setgroups process retains supplementary groups
        if (initgroups(pwd->pw_name, pwd->pw_gid) != 0) {
            fprintf(stderr, "initgroups failed, check -u option\n");
            return -1;
        }
#endif
        if (setuid(pwd->pw_uid) != 0) {
            fprintf(stderr, "setuid failed, check -u option\n");
            return -1;
        }
#else
        fprintf(stderr, "-u not supported on this platform");
        return -1;
#endif
    }

    // initialize the shib-target library
    SPConfig& conf=SPConfig::getConfig();
    conf.setFeatures(
        SPConfig::Listener |
        SPConfig::Caching |
        SPConfig::Metadata |
        SPConfig::Trust |
        SPConfig::Credentials |
        SPConfig::AttributeResolution |
        SPConfig::Handlers |
        SPConfig::OutOfProcess |
        (shar_checkonly ? SPConfig::RequestMapping : SPConfig::Logging)
        );
    if (!conf.init(shar_schemadir, shar_prefix)) {
        fprintf(stderr, SD_ERR "configuration is invalid, check console or log for specific problems\n");
        return -1;
    }

    if (daemonize) {
        // We must fork() early, while we're single threaded.
        // StorageService cleanup thread is about to start.
        switch (fork()) {
            case 0:
                break;
            case -1:
                perror("forking");
                exit(EXIT_FAILURE);
            default:
                sleep(daemon_wait);
                exit(shibd_running ? EXIT_SUCCESS : EXIT_FAILURE);
        }
    }

    if (!conf.instantiate(shar_config)) {
        fprintf(stderr, SD_ERR "configuration is invalid, check console or log for specific problems\n");
        conf.term();
        return -2;
    }

    if (shar_checkonly)
        fprintf(stderr, "overall configuration is loadable, check console or log for non-fatal problems\n");
    else {
        // Init the listener.
        ListenerService* listener = conf.getServiceProvider()->getListenerService();
        if (!listener->init(unlink_socket)) {
            fprintf(stderr, SD_ERR "listener failed to initialize\n");
            conf.term();
            return -3;
        }

        if (daemonize) {
            if (setsid() == -1) {
                perror("setsid");
                exit(EXIT_FAILURE);
            }
            if (chdir("/") == -1) {
                perror("chdir to root");
                exit(EXIT_FAILURE);
            }

            if (pidfile) {
                FILE* pidf = fopen(pidfile, "w");
                if (pidf) {
                    fprintf(pidf, "%d\n", getpid());
                    fclose(pidf);
                }
                else {
                    perror(pidfile);
                }
            }

            freopen("/dev/null", "r", stdin);
            freopen("/dev/null", "w", stdout);
            freopen("/dev/null", "w", stderr);

            // Signal our parent that we are A-OK.
            kill(getppid(), SIGUSR1);
        }

        // Run the listener.
#ifdef HAVE_SD_NOTIFY
        sd_notify(0, "READY=1");
#endif
        if (!listener->run(&shibd_shutdown)) {
            fprintf(stderr, SD_ERR "listener failure during service\n");
            listener->term();
            conf.term();
            if (daemonize && pidfile)
                unlink(pidfile);
            return -3;
        }
        listener->term();
    }
#ifdef HAVE_SD_NOTIFY
    sd_notify(0, "STOPPING=1");
#endif
    conf.term();
    if (daemonize && pidfile)
        unlink(pidfile);
    return 0;
}

#endif

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
 * shar_win32.cpp -- the SHAR "main" code on Win32
 *
 * Created By:	Scott Cantor (cantor.2@osu.edu)
 *
 * $Id$
 */

#include "config_win32.h"
#include "shar-utils.h"

extern int shar_run;                    // signals shutdown to Unix side
extern const char* shar_schemadir;
extern const char* shar_config;
extern bool shar_checkonly;

// internal variables
SERVICE_STATUS          ssStatus;       // current status of the service
SERVICE_STATUS_HANDLE   sshStatusHandle;
DWORD                   dwErr = 0;
BOOL                    bConsole = FALSE;
char                    szErr[256];
LPCSTR                  lpszInstall = NULL;
LPCSTR                  lpszRemove = NULL;

// internal function prototypes
VOID WINAPI service_ctrl(DWORD dwCtrlCode);
VOID WINAPI service_main(DWORD dwArgc, LPSTR *lpszArgv);
VOID CmdInstallService(LPCSTR);
VOID CmdRemoveService(LPCSTR);
LPTSTR GetLastErrorText( LPSTR lpszBuf, DWORD dwSize );

BOOL LogEvent(
    LPCTSTR  lpUNCServerName,
    WORD  wType,
    DWORD  dwEventID,
    PSID  lpUserSid,
    LPCTSTR  message);

VOID ServiceStart(DWORD dwArgc, LPSTR *lpszArgv);
VOID ServiceStop();
BOOL ReportStatusToSCMgr(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);
void AddToMessageLog(LPSTR lpszMsg);

BOOL WINAPI BreakHandler(DWORD dwCtrlType)
{
   switch(dwCtrlType)
    {
        case CTRL_BREAK_EVENT:  // use Ctrl+C or Ctrl+Break to simulate
        case CTRL_C_EVENT:      // SERVICE_CONTROL_STOP in console mode
            ServiceStop();
            return TRUE;
    }
    return FALSE;
}


int real_main(int);  // The revised two-phase main() in shar.cpp

int main(int argc, char *argv[])
{
    int i=1;
    while ((argc > i) && ((*argv[i] == '-') || (*argv[i] == '/')))
    {
        if (_stricmp("install", argv[i]+1) == 0)
        {
            if (argc > ++i)
                lpszInstall = argv[i++];
        }
        else if (_stricmp("remove", argv[i]+1) == 0)
        {
            if (argc > ++i)
                lpszRemove = argv[i++];
        }
        else if (_stricmp( "console", argv[i]+1) == 0)
        {
            i++;
            bConsole = TRUE;
        }
        else if (_stricmp( "check", argv[i]+1) == 0)
        {
            i++;
            bConsole = TRUE;
            shar_checkonly=true;
        }
        else if (_stricmp( "config", argv[i]+1) == 0)
        {
            if (argc > ++i)
                shar_config = argv[i++];
        }
        else if (_stricmp( "schemadir", argv[i]+1) == 0)
        {
            if (argc > ++i)
                shar_schemadir = argv[i++];
        }
        else
        {
            goto dispatch;
        }
    }
    
    if (bConsole)
    {
        // Install break handler, then run the C routine twice, once to setup, once to start running.
        SetConsoleCtrlHandler(&BreakHandler,TRUE);
        if (real_main(1)!=0)
        {
            LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, "SHAR startup failed, check shar log for help.");
            return -1;
        }
        return real_main(0);
    }
    else if (lpszInstall)
    {
        CmdInstallService(lpszInstall);
        return 0;
    }
    else if (lpszRemove)
    {
        CmdRemoveService(lpszRemove);
        return 0;
    }
    

    // if it doesn't match any of the above parameters
    // the service control manager may be starting the service
    // so we must call StartServiceCtrlDispatcher
    dispatch:
        // this is just to be friendly
        printf("%s -install <name>   to install the named service\n", argv[0]);
        printf("%s -remove <name>    to remove the named service\n", argv[0]);
        printf("%s -console          to run as a console app for debugging\n", argv[0]);
        printf("%s -check            to run as a console app and check configuration\n", argv[0]);
        printf("\t-config <file> to specify the config file to use\n");
        printf("\t-schemadir <dir> to specify where schemas are\n");
        printf("\nService starting.\nThis may take several seconds. Please wait.\n" );

    SERVICE_TABLE_ENTRY dispatchTable[] =
    {
        { "SHAR", (LPSERVICE_MAIN_FUNCTION)service_main },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcher(dispatchTable))
        LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, "StartServiceCtrlDispatcher failed.");
    return 0;
}

//
//  FUNCTION: ServiceStart
//
//  PURPOSE: Actual code of the service
//          that does the work.
//
VOID ServiceStart (DWORD dwArgc, LPSTR *lpszArgv)
{

    if (real_main(1)!=0)
    {
        LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, "SHAR startup failed, check shar log for help.");
        return;
    }

    LogEvent(NULL, EVENTLOG_INFORMATION_TYPE, 7700, NULL, "SHAR started successfully.");

    if (!ReportStatusToSCMgr(SERVICE_RUNNING, NO_ERROR, 0))
        return;

    real_main(0);
}


//
//  FUNCTION: ServiceStop
//
//   PURPOSE: Stops the service
//
VOID ServiceStop()
{
    if (!bConsole)
        LogEvent(NULL, EVENTLOG_INFORMATION_TYPE, 7701, NULL, "SHAR stopping...");
    shar_run=0;
}


void WINAPI service_main(DWORD dwArgc, LPSTR *lpszArgv)
{

    // register our service control handler:
    sshStatusHandle=RegisterServiceCtrlHandler(lpszArgv[0], service_ctrl);
    if (!sshStatusHandle)
        goto cleanup;

    // SERVICE_STATUS members that don't change in example
    ssStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ssStatus.dwServiceSpecificExitCode = 0;


    // report the status to the service control manager.
    if (!ReportStatusToSCMgr(
        SERVICE_START_PENDING, // service state
        NO_ERROR,              // exit code
        3000))                 // wait hint
        goto cleanup;


    ServiceStart(dwArgc, lpszArgv);

cleanup:

    // try to report the stopped status to the service control manager.
    //
    if (sshStatusHandle)
        (VOID)ReportStatusToSCMgr(
                            SERVICE_STOPPED,
                            dwErr,
                            0);

    return;
}


//
//  FUNCTION: service_ctrl
//
//  PURPOSE: This function is called by the SCM whenever
//           ControlService() is called on this service.
//
//  PARAMETERS:
//    dwCtrlCode - type of control requested
//
//  RETURN VALUE:
//    none
//
VOID WINAPI service_ctrl(DWORD dwCtrlCode)
{
    // Handle the requested control code.
    //
    switch(dwCtrlCode)
    {
        // Stop the service.
        //
        case SERVICE_CONTROL_STOP:
            ssStatus.dwCurrentState = SERVICE_STOP_PENDING;
            ServiceStop();
            break;

        // Update the service status.
        //
        case SERVICE_CONTROL_INTERROGATE:
            break;

        // invalid control code
        //
        default:
            break;

    }

    ReportStatusToSCMgr(ssStatus.dwCurrentState, NO_ERROR, 0);
}


//
//  FUNCTION: ReportStatusToSCMgr()
//
//  PURPOSE: Sets the current status of the service and
//           reports it to the Service Control Manager
//
//  PARAMETERS:
//    dwCurrentState - the state of the service
//    dwWin32ExitCode - error code to report
//    dwWaitHint - worst case estimate to next checkpoint
//
//  RETURN VALUE:
//    TRUE  - success
//    FALSE - failure
//
BOOL ReportStatusToSCMgr(DWORD dwCurrentState,
                         DWORD dwWin32ExitCode,
                         DWORD dwWaitHint)
{
    static DWORD dwCheckPoint = 1;
    BOOL fResult = TRUE;


    if (!bConsole) // when console we don't report to the SCM
    {
        if (dwCurrentState == SERVICE_START_PENDING)
            ssStatus.dwControlsAccepted = 0;
        else
            ssStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

        ssStatus.dwCurrentState = dwCurrentState;
        ssStatus.dwWin32ExitCode = dwWin32ExitCode;
        ssStatus.dwWaitHint = dwWaitHint;

        if ( ( dwCurrentState == SERVICE_RUNNING ) ||
             ( dwCurrentState == SERVICE_STOPPED ) )
            ssStatus.dwCheckPoint = 0;
        else
            ssStatus.dwCheckPoint = dwCheckPoint++;


        // Report the status of the service to the service control manager.
        //
        if (!(fResult = SetServiceStatus(sshStatusHandle, &ssStatus)))
            LogEvent(NULL, EVENTLOG_ERROR_TYPE, 2100, NULL, "SetServiceStatus failed.");
    }
    return fResult;
}


///////////////////////////////////////////////////////////////////
//
//  The following code handles service installation and removal
//
//
void CmdInstallService(LPCSTR name)
{
    SC_HANDLE   schService;
    SC_HANDLE   schSCManager;

    char szPath[256];
    char dispName[512];
    char realName[512];
    char cmd[2048];

    if ( GetModuleFileName( NULL, szPath, 256 ) == 0 )
    {
        printf("Unable to install %s - %s\n", name, GetLastErrorText(szErr, 256));
        return;
    }
    
    sprintf(dispName,"Shibboleth Attribute Requester (%s)",name);
    sprintf(realName,"SHAR_%s",name);
    if (shar_config && shar_schemadir)
        sprintf(cmd,"%s -config %s -schemadir %s",szPath,shar_config,shar_schemadir);
    else if (shar_config)
        sprintf(cmd,"%s -config %s",szPath,shar_config);
    else if (shar_schemadir)
        sprintf(cmd,"%s -schemadir %s",szPath,shar_schemadir);
    else
        sprintf(cmd,"%s",szPath);

    schSCManager = OpenSCManager(
                        NULL,                   // machine (NULL == local)
                        NULL,                   // database (NULL == default)
                        SC_MANAGER_ALL_ACCESS   // access required
                        );
    
    
    if ( schSCManager )
    {
        schService = CreateService(
            schSCManager,               // SCManager database
            realName,                   // name of service
            dispName,                   // name to display
            SERVICE_ALL_ACCESS,         // desired access
            SERVICE_WIN32_OWN_PROCESS,  // service type
            SERVICE_AUTO_START,         // start type
            SERVICE_ERROR_NORMAL,       // error control type
            cmd,                        // service's command line
            NULL,                       // no load ordering group
            NULL,                       // no tag identifier
            NULL,                       // dependencies
            NULL,                       // LocalSystem account
            NULL);                      // no password

        if ( schService )
        {
            printf("%s installed.\n",realName);
            CloseServiceHandle(schService);
        }
        else
        {
            printf("CreateService failed - %s\n", GetLastErrorText(szErr, 256));
        }

        CloseServiceHandle(schSCManager);
    }
    else
        printf("OpenSCManager failed - %s\n", GetLastErrorText(szErr,256));
}

void CmdRemoveService(LPCSTR name)
{
    SC_HANDLE   schService;
    SC_HANDLE   schSCManager;
    char        realName[512];

    sprintf(realName,"SHAR_%s",name);

    schSCManager = OpenSCManager(
                        NULL,                   // machine (NULL == local)
                        NULL,                   // database (NULL == default)
                        SC_MANAGER_ALL_ACCESS   // access required
                        );
    if ( schSCManager )
    {
        schService = OpenService(schSCManager, realName, SERVICE_ALL_ACCESS);

        if (schService)
        {
            // try to stop the service
            if ( ControlService( schService, SERVICE_CONTROL_STOP, &ssStatus ) )
            {
                printf("Stopping SHAR (%s).", name);
                Sleep( 1000 );

                while( QueryServiceStatus( schService, &ssStatus ) )
                {
                    if ( ssStatus.dwCurrentState == SERVICE_STOP_PENDING )
                    {
                        printf(".");
                        Sleep( 1000 );
                    }
                    else
                        break;
                }

                if ( ssStatus.dwCurrentState == SERVICE_STOPPED )
                    printf("\n%s stopped.\n", realName);
                else
                    printf("\n%s failed to stop.\n", realName);

            }

            // now remove the service
            if( DeleteService(schService) )
                printf("%s removed.\n", realName);
            else
                printf("DeleteService failed - %s\n", GetLastErrorText(szErr,256));


            CloseServiceHandle(schService);
        }
        else
            printf("OpenService failed - %s\n", GetLastErrorText(szErr,256));

        CloseServiceHandle(schSCManager);
    }
    else
        printf("OpenSCManager failed - %s\n", GetLastErrorText(szErr,256));
}


//
//  FUNCTION: GetLastErrorText
//
//  PURPOSE: copies error message text to string
//
//  PARAMETERS:
//    lpszBuf - destination buffer
//    dwSize - size of buffer
//
//  RETURN VALUE:
//    destination buffer
//
//  COMMENTS:
//
LPTSTR GetLastErrorText( LPSTR lpszBuf, DWORD dwSize )
{
    DWORD dwRet;
    LPSTR lpszTemp = NULL;

    dwRet = FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |FORMAT_MESSAGE_ARGUMENT_ARRAY,
                           NULL,
                           GetLastError(),
                           LANG_NEUTRAL,
                           (LPSTR)&lpszTemp,
                           0,
                           NULL );

    // supplied buffer is not long enough
    if ( !dwRet || ( (long)dwSize < (long)dwRet+14 ) )
        lpszBuf[0] = '\0';
    else
    {
        lpszTemp[lstrlen(lpszTemp)-2] = '\0';  //remove cr and newline character
        sprintf( lpszBuf, "%s (0x%x)", lpszTemp, GetLastError() );
    }

    if ( lpszTemp )
        LocalFree((HLOCAL) lpszTemp );

    return lpszBuf;
}

BOOL LogEvent(
    LPCSTR  lpUNCServerName,
    WORD  wType,
    DWORD  dwEventID,
    PSID  lpUserSid,
    LPCSTR  message)
{
    LPCSTR  messages[] = {message, NULL};
    
    HANDLE hElog = RegisterEventSource(lpUNCServerName, "Shibboleth Attribute Requester");
    BOOL res = ReportEvent(hElog, wType, 0, dwEventID, lpUserSid, 1, 0, messages, NULL);
    return (DeregisterEventSource(hElog) && res);
}

@echo off

setlocal
echo Just add code
exit /b

REM
REM EXAMPLE batch file to set restrictive ACLs on a Shibboleth IdP installation.

REM NEEDS TO BE SP AGENTIFIED

sERVER ACCOUNT:
REM Default [IIS] IIS APPPOOL\DefaultAppPool
Rem Defailt (non-iis) "*S-1-5-19" (local_service)
Administrators: "*S-1-5-32-544"
Users: "*S-1-5-32-545"
local_system "*S-1-5-18"


REM
REM You should consider this a sample rather than set in stone and adapt it for
REM your own use
REM
REM Two optional Parameters:
REM    The first is the ID to be given explicit read access to the configuration
REM    and write access to the logs.  This could be the OD or a low priv user you
REM    run the container as
REM
REM    The second is the ID to be given ownership of the files.  This finesses an
REM    issue wherebywhich happen if the owner of the files is not given access.
REM    The directory tree then becaomes an unmaintainable mess.
REM
REM    Defaults to 'Administrators'
REM

if "%2%" EQU "" (
   set OWNER_ID=Administrators
) else (
   set OWNER_ID=%2%
)

REM
REM First up, take ownership
REM   /t means recursive

echo Setting owner to %OWNER_ID%
icacls "%~dp0\.." /t /setowner %OWNER_ID% /q

if ERRORLEVEL 1 (
   echo Error: Could not set ownership
   goto done
)

REM 

if "%1%"=="" (
   REM Set the ACLS Default ACLS
   REM   /t recursive
   REM   /inheritance:r Remove inherited ACLS
   REM   /grant:r ID:(CI)(OI)(F) Full access for ID (replacing any existing)
   REM   /grant:r ID:(CI)(OI)(F) Full access for ID (replacing any existing, but causing kids to be inherited) DIRECTORIES ONLY

   echo Setting FULL ACL on dirs for SYSTEM and Administrators
   icacls "%~dp0\.." /t /inheritance:r /grant:r "SYSTEM:(OI)(CI)(F)" "Administrators:(OI)(CI)(F)" /q
   if ERRORLEVEL 1 (
      echo Error: Could not set ACL
      goto done
   )

   echo Setting FULL ACL on files for SYSTEM and Administrators
   icacls "%~dp0\.." /t /inheritance:r /grant:r SYSTEM:F Administrators:F /q
   if ERRORLEVEL 1 (
      echo Error: Could not set ACL
      goto done
   )

) else (
   REM As above, but add read for the supplied user
   REM GR=GENERIC_READ RD=READ_DATA/ENUMERATE_DIR X=EXECUTE/TRAVERSE_DIR

   echo Setting FULL ACL with inheritance on dirs for SYSTEM and Administrators, Readonly ACL for %1%
   icacls "%~dp0\.." /t /inheritance:r /grant:r "SYSTEM:(OI)(CI)(F)" "Administrators:(OI)(CI)(F)" "%1%:(OI)(CI)(GR,RD,X)" /q
   if ERRORLEVEL 1 (
      echo Error: Could not set ACL
      goto done
   )

   echo Setting FULL ACL with inheritance on files for  SYSTEM and Administrators, Readonly ACL for %1%
   icacls "%~dp0\.." /t /inheritance:r /grant:r SYSTEM:F Administrators:F "%1%:(GR,RD,X)" /q
   if ERRORLEVEL 1 (
      echo Error: Could not set ACL
      goto done
   )

   REM And the logs
   echo Setting FULL ACL on logs directory for SYSTEM,  Administrators and %1%
   icacls "%~dp0\..\logs" /t /inheritance:r /grant:r "SYSTEM:(OI)(CI)(F)" "Administrators:(OI)(CI)(F)" "%1%:(OI)(CI)(F)" /q
   if ERRORLEVEL 1 (
      echo Error: Could not set ACL
      goto done
   )

   echo Setting FULL ACL on logs directory content for SYSTEM,  Administrators and %1%
   icacls "%~dp0\..\logs" /t /inheritance:r /grant:r SYSTEM:F Administrators:F "%1%:F" /q
   if ERRORLEVEL 1 (
      echo Error: Could not set ACL
      goto done
   )
)

:done

exit /b

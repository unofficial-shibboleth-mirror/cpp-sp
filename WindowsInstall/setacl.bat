@echo off
setlocal
echo Just add code

Rem
Rem EXAMPLE batch file to set restrictive ACLs on a Shibboleth Hub installation.
Rem
Rem You should consider this a sample rather than set in stone and adapt it for
Rem your own use
Rem

Rem
Rem Make a guess for the Server account
Rem
Rem Documentation for SIDS
Rem https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids and
Rem https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-special-identities-groups#local-service
Rem

if exist %SYSTEMROOT%\System32\INETSRV\appcmd.exe (
   Set SERVER_ACCOUNT_DEFAULT="IIS APPPOOL\DefaultAppPool"
) Else (
   Set SERVER_ACCOUNT_DEFAULT="*S-1-5-19"
   Rem *S-1-5-19 is "Local Service
)

Rem
Rem the server account gets GENERIC_READ EXECUTE access to etc and lib and
Rem GENERIC_ALL access to the var directory
Rem

Set /p SERVER_ACCOUNT="Server Account [%SERVER_ACCOUNT_DEFAULT%] "
if "%SERVER_ACCOUNT%" == "" (
   Set SERVER_ACCOUNT=%SERVER_ACCOUNT_DEFAULT%
)

Rem
Rem Set other sids
Rem
Rem Administrators Account and LocalSystem get GENERIC_ALL to the installation
Rem
Set ADMINISTRATORS_ACCOUNT="*S-1-5-32-544"
Set LOCAL_SYSTEM_ACCOUNT="*S-1-5-18"
Rem
Rem Users get nothing
Rem
Set USERS_ACCOUNT="*S-1-5-32-545"

Rem
Rem Root of the Install
Rem This bat file is <Root>\bin\Shibboleth-sp\SetAcl.bat
Rem

cd /d "%~dp0\..\..\"
Set INSTALL_ROOT=%CD%

echo Setting owner to %ADMINISTRATORS_ACCOUNT%
icacls "%INSTALL_ROOT%" /t /setowner %ADMINISTRATORS_ACCOUNT% /q

Rem
Rem Start to lock down
Rem use Icacls
Rem https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls
Rem
Rem   /t recursive
Rem   /inheritance:r Remove inherited ACLS
Rem   /grant:r ID:(CI)(OI)(F) Full access for ID (replacing any existing)
Rem   /grant:r ID:(CI)(OI)(F) Full access for ID (replacing any existing, but causing kids to be inherited) DIRECTORIES ONLY
Rem       CI Container Inherit
Rem       OI Object Inherit
Rem       N None
Rem       F Full
Rem       GR GenericRead
Rem       RD ReadData/ListDirectory
Rem       X Execute


echo Protecting %INSTALL_ROOT%\lib

Rem lib
Rem  Admins:        Everything
Rem  Local System:  Everything
Rem  Server:        ReadOnly
Rem  Esers:         Nothing
Rem directory first
icacls "%INSTALL_ROOT%\lib" /t /inheritance:r /grant:r "%ADMINISTRATORS_ACCOUNT%:(OI)(CI)(F)" \
                       "%LOCAL_SYSTEM_ACCOUNT%:(OI)(CI)(F)" \
                       "%SERVER_ACCOUNT%:(OI)(CI)(GR,RD,X)" \
                       "%USERS_ACCOUNT$:(OI)(CI)(N)"
Rem Files
icacls "%INSTALL_ROOT%\lib" /t /inheritance:r /grant:r "%ADMINISTRATORS_ACCOUNT%:F" \
                       "%LOCAL_SYSTEM_ACCOUNT%:F" \
                       "%SERVER_ACCOUNT%:(GR,RD,X)" \
                       "%USERS_ACCOUNT$:N"

Rem etc - same as lib
Rem Directories
icacls "%INSTALL_ROOT%\etc" /t /inheritance:r /grant:r "%ADMINISTRATORS_ACCOUNT%:(OI)(CI)(F)" \
                       "%LOCAL_SYSTEM_ACCOUNT%:(OI)(CI)(F)" \
                       "%SERVER_ACCOUNT%:(OI)(CI)(GR,RD,X)" \
                       "%USERS_ACCOUNT$:(OI)(CI)(N)"
Rem Lib Files
icacls "%INSTALL_ROOT%\lib" /t /inheritance:r /grant:r "%ADMINISTRATORS_ACCOUNT%:F" \
                       "%LOCAL_SYSTEM_ACCOUNT%:F" \
                       "%SERVER_ACCOUNT%:(GR,RD,X)" \
                       "%USERS_ACCOUNT$:N"

Rem bin - same as lib
Rem Directories
icacls "%INSTALL_ROOT%\bin" /t /inheritance:r /grant:r "%ADMINISTRATORS_ACCOUNT%:(OI)(CI)(F)" \
                       "%LOCAL_SYSTEM_ACCOUNT%:(OI)(CI)(F)" \
                       "%SERVER_ACCOUNT%:(OI)(CI)(GR,RD,X)" \
                       "%USERS_ACCOUNT$:(OI)(CI)(N)"
Rem Lib Files
icacls "%INSTALL_ROOT%\bin" /t /inheritance:r /grant:r "%ADMINISTRATORS_ACCOUNT%:F" \
                       "%LOCAL_SYSTEM_ACCOUNT%:F" \
                       "%SERVER_ACCOUNT%:(GR,RD,X)" \
                       "%USERS_ACCOUNT$:N"
Rem cache
Rem  Admins:        Everything
Rem  Local System:  Everything
Rem  Server:        Everything
Rem  Esers:         Nothing
Rem directory first
Rem Directories
icacls "%INSTALL_ROOT%\cache" /t /inheritance:r /grant:r "%ADMINISTRATORS_ACCOUNT%:(OI)(CI)(F)" \
                       "%LOCAL_SYSTEM_ACCOUNT%:(OI)(CI)(F)" \
                       "%SERVER_ACCOUNT%:(OI)(CI)(F)" \
                       "%USERS_ACCOUNT$:(OI)(CI)(N)"
Rem Lib Files
icacls "%INSTALL_ROOT%\cache" /t /inheritance:r /grant:r "%ADMINISTRATORS_ACCOUNT%:F" \
                       "%LOCAL_SYSTEM_ACCOUNT%:F" \
                       "%SERVER_ACCOUNT%:F" \
                       "%USERS_ACCOUNT$:N"



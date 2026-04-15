Rem @echo off
Rem Install SP agent

setlocal

Rem Find FQP for root of installation
set SAVE_WORKING_DIR=%cd%
cd /d %~dp0
set SOURCE_DIR=%cd%

Rem - Collect targetDir [opt\shibboleth-sp]
set loc=%SystemDrive%\opt\shibboleth-sp
set /p TargetDir="Location To Install [%loc%] :"
if "%TargetDir%" == "" set TargetDir=%loc%

Rem - Fail if lib or bin exist
if exist "%TargetDir%\bin\shibboleth-sp" (
    echo %TargetDir%\bin\shibboleth-sp exists.  Agent may already be installed
    echo Did you mean %TargetDir%\bin\shibboleth-sp\update ?
    exit /b
)
if exist "%TargetDir%\lib\shibboleth-sp" (
    echo %TargetDir%\lib\shibboleth-sp exists.  Agent may already be installed
    echo Did you mean %TargetDir%\bin\shibboleth-sp\update ?
    exit /b
)

Rem Call generic "install/update" bar file shipped with this release

mkdir  "%targetDir%"
cmd /c dist\dist-bin\doupdate.bat "%targetDir%"

Rem TODOODOTODO nativelogmessage into registry

Rem Detect IIS and configure if there

if exist %SYSTEMROOT%\System32\INETSRV\appcmd.exe (
    echo Installing ShibAgent module into IIS
    %SYSTEMROOT%\System32\INETSRV\appcmd.exe install module /name:ShibAgent /image:"%TargetDir%\lib\shibboleth-sp\iis_shib4.dll"
)

Rem Aak to update ACLs and if so CALL SETACL

:loop
set /p YesNo="Run SetAcl.bat [Yn] "
if /i "%YesNo%"=="n" exit /b
if /i not "%YesNo%"=="y" goto loop

cmd/c %TargetDir%\bin\shibboleth-sp\setacl.bat

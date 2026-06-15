@echo off
Rem Install SP agent

Rem probe for admin
net session 1> nul 2> nul
if %errorlevel% NEQ 0 (
   Echo Cannot install kit.  This command needs to be run with administrative rights.
   exit /b
)

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

Rem Call generic "install/update" bat file shipped with this release

if not exist "%targetDir%" mkdir  "%targetDir%"
cmd /c dist\dist-bin\doupdate.bat "%targetDir%"

Rem Detect IIS and configure if there

if exist %SYSTEMROOT%\System32\INETSRV\appcmd.exe (
    echo Installing ShibAgent module into IIS
    %SYSTEMROOT%\System32\INETSRV\appcmd.exe install module /name:ShibAgent /image:"%TargetDir%\lib\shibboleth-sp\iis_shib4.dll"
)

Rem Ask whether to update ACLs and if so CALL SETACL

:loop
set /p YesNo="Run SetAcl.bat [Yn] "
if /i "%YesNo%"=="n" exit /b
if /i not "%YesNo%"=="y" goto loop

cmd/c %TargetDir%\bin\shibboleth-sp\setacl.bat

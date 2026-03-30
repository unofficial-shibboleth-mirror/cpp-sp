@echo off
REM Install SP agent

setlocal

rem Find FQP for root of installation
set SAVE_WORKING_DIR=%cd%
cd /d %~dp0
set SOURCE_DIR=%cd%

rem - Collect targetDir [opt\shibboleth-sp]
set loc=%SystemDrive%\opt\shibboleth-sp
set /p TargetDir="Location To Install [%loc%] :"
if "%TargetDir%" == "" ( set TargetDir=%loc%

rem - Fail if lib or bin exist
if exist %TargetDir%\bin\shibboleth-sp (
   echo %TargetDir%\bin\shibboleth-sp exists.  Agent may already be installed
   echo Did you bean %TargetDir%\bin\shibboleth-sp\update ?
   exit /b
)
if exist %TargetDir%\lib\shibboleth-sp (
   echo %TargetDir%\lib\shibboleth-sp exists.  Agent may already be installed
   echo Did you bean %TargetDir%\bin\shibboleth-sp\update ?
   exit /b
)

Rem Call generic "install/update" bar file shipped with this release

dist-bin\doupdate.bat "%targetDir%"

Rem Detect IIS and configure if there

if exist %SYSTEMROOT%\INETSRV\appcmd.exe (
    echo Installing ShibAgent module into IIS
    %SYSTEMROOT%\INETSRV\appcmd.exe install module /name:ShibAgent /image:"%TargetDir%\lib\shibboleth-sp\iis_shib4.dll"
)

Rem Aak to update ACLs and if so CALL SETACL

:loop
set /p YesNo="Run SetAcl.bat [Yn] "
if /i "%YesNo%"=="n" goto  exit
if /i not "%YesNo%"=="y" goto loop

%TargetDir%\bin\shibboleth-sp\setacl.bat

:exit
cd /d %SAVE_WORKING_DIR%
exit /b

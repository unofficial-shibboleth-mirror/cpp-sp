setlocal
REM
REM File to uninstall the SP agent
REM

Rem Goto root of install - we are running from %targetDir%\dist-4.x.7\dist-bin\

cd /d %1%
set TargetDir=%cd%

if not exist "%targetdir%\bin\shibboleth-sp" (
   echo "No installation found %targetdir%
   exit /b
)

if exist %SYSTEMROOT%\System32\INETSRV\appcmd.exe (
    echo Uninstalling ShibAgent module from IIS
    %SYSTEMROOT%\System32\INETSRV\appcmd.exe delete module ShibAgent
    %SYSTEMROOT%\System32\INETSRV\appcmd.exe uninstall module ShibAgent
)

echo Removing %TargetDir%\bin\shibboleth-sp\
rd /s /q "%TargetDir%\bin\shibboleth-sp"

echo Removing %TargetDir%\lib\shibboleth-sp\
rd /s /q "%TargetDir%\lib\shibboleth-sp"

echo Not touching %TargetDir%\etc\shibboleth-sp\

echo "just add code to remove [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{D9DA52E3-F96E-4C84-B153-C3B17C34F730}]" and reg keys

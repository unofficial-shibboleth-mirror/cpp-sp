setlocal
REM
REM File to uninstall the SP agent
REM

Rem Goto root of install - we are running from %targetDir%\dist-4.x.7\dist-bin\

cd %dp0..\.
if exist %SYSTEMROOT%\System32\INETSRV\appcmd.exe (
    echo Uninstalling ShibAgent module from IIS
    %SYSTEMROOT%\System32\INETSRV\appcmd.exe delete module ShibAgent
    %SYSTEMROOT%\System32\INETSRV\appcmd.exe uninstall module ShibAgent
)
set base=%cd%

echo Removing %base%\bin\shibboleth-sp\
rd /s /q "%base%\bin\shibboleth-sp"

echo Removing %base%\lib\shibboleth-sp\
rd /s /q "%base%\lib\shibboleth-sp"

echo Not touching %base%\etc\shibboleth-sp\

echo "just add code to remove [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{D9DA52E3-F96E-4C84-B153-C3B17C34F730}]" and reg keys

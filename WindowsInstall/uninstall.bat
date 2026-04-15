setlocal
Rem
Rem File to uninstall the SP agent
Rem
Rem This file is found in a non-standard location of an install
Rem (/opt/shibboleth-sp/bin, as a peer to /opt/shibboleth-sp/bin/shibboleth-sp)
Rem (so it doesn't delete itself).  It is really only expected to
Rem be run from the "uninstall" menu item of the apps and features
Rem but it is idempotent so can be run any time.

cd /d %~dp0

if exist %SYSTEMROOT%\System32\INETSRV\appcmd.exe (
    echo Uninstalling ShibAgent module from IIS
    %SYSTEMROOT%\System32\INETSRV\appcmd.exe delete module ShibAgent 2> nul:
    %SYSTEMROOT%\System32\INETSRV\appcmd.exe uninstall module ShibAgent  2> nul:
)

echo "Removing bat files"
rd /s /q shibboleth-sp

cd ..\lib
echo "Removing library files"
rd /s /q shibboleth-sp

Echo Not touching configuration files

Rem remove from "installed apps & Features"
reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{D9DA52E3-F96E-4C84-B153-C3B17C34F730} /f
Rem and from logging
reg delete HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Shibboleth\ShibbolethSPAgent /f

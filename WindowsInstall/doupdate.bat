Rem @echo off
Rem Update SP agent

setlocal

Rem Find FQP for target and root of installation
set SAVE_WORKING_DIR=%cd%
cd /d %1%
set TargetDir=%cd%

cd /d %~dp0
set SourceDir=%cd%
cd ..
echo "Installing from %cd%"

Rem Grab version as string
for /f "delims=" %%a IN (version.txt) do (set /a Version=%%a)
Set /a MajorVersion="%VERSION% >> 24" > nul:
Set /a MinorVersion="(%VERSION% >> 16) & 0xFF" > nul:
Set /a PatchVersion = "%VERSION% & 0xFFFF" > nul:
set VersionString=%MajorVersion%.%MinorVersion%.%PatchVersion%

if exist %TargetDir%\lib\shibboleth-sp (
  Echo Updating SP Agent Version %VersionString%
) else (
  Echo Installing SP Agent Version %VersionString%
)

Rem
Rem use robocopy to copy stuff over
Rem /s recursive
Rem /is copy eveything
Rem /njh No job header
Rem /njs No job summary
echo Copying Distribution to %targetDir%\dist-%VersionString%
mkdir  "%targetDir%\dist-%VersionString%"
robocopy /s /is /njs /njh . "%targetDir%\dist-%VersionString%"

echo Copying Batch Files to %targetdir%\bin\shibboleth-sp\
mkdir  "%targetdir%\bin\shibboleth-sp\"
robocopy /is /njs /njh bin "%targetdir%\bin\shibboleth-sp"
copy /y dist-bin\uninstall.bat "%targetdir%\bin"

echo Copying Dll Files to  %targetdir%\lib\shibboleth-sp\
mkdir "%targetdir%\lib\shibboleth-sp\"
robocopy /is /njs /njh lib "%targetdir%\lib\shibboleth-sp"

Rem /xc /xn /xo only new files
Rem  /xc exclude existing files same timestamp different sizes
Rem  /xn exclude newer
Rem  /xo exclude older
Rem Hence /xo /xc /xn means "copy every file where a file of that name isn't there"
echo Copying new config Files
mkdir "%targetdir%\etc\shibboleth-sp\"
robocopy /xc /xn /xo /njs /njh etc "%targetdir%\etc\shibboleth-sp"

Rem Set registry
Rem Firstly the "have I been installed" setting

reg import dist-bin\regkeys.txt
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{D9DA52E3-F96E-4C84-B153-C3B17C34F730} /f /v DisplayIcon /t REG_SZ /d "%SourceDir%\shib.ico,0"
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{D9DA52E3-F96E-4C84-B153-C3B17C34F730} /f /v InstallSource /t REG_SZ /d "%SourceDir%"
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{D9DA52E3-F96E-4C84-B153-C3B17C34F730} /f /v Version /t REG_DWORD /d %Version%
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{D9DA52E3-F96E-4C84-B153-C3B17C34F730} /f /v DisplayVersion /t REG_SZ /d "%VersionString%"
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{D9DA52E3-F96E-4C84-B153-C3B17C34F730} /f /v VersionMinor /t REG_DWORD /d %MinorVersion%
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{D9DA52E3-F96E-4C84-B153-C3B17C34F730} /f /v InstallLocation /t REG_SZ /d "%TargetDir%"
Rem note double quoting for "
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{D9DA52E3-F96E-4C84-B153-C3B17C34F730} /f /v UninstallString /t REG_SZ /d "cmd /c ""%targetdir%\bin\uninstall.bat"""

Rem
Rem now the event viewer
Rem
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Shibboleth\Shibboleth Service Provider" /f /v CategoryCount /t REG_DWORD /d 0
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Shibboleth\Shibboleth Service Provider" /f /v TypesSupported /t REG_DWORD /d 7
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Shibboleth\Shibboleth Service Provider" /f /v CategoryMessageFile /t REG_SZ /d "%TargetDir%\lib\shibboleth-sp\NTEventLogAppender.dll"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Shibboleth\Shibboleth Service Provider" /f /v EventMessageFile /t REG_SZ /d "%TargetDir%\lib\shibboleth-sp\NTEventLogAppender.dll"

exit /b

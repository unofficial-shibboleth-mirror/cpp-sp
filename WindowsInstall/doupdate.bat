Rem @echo off
Rem Update SP agent

setlocal

Rem Find FQP for target and root of installation
set SAVE_WORKING_DIR=%cd%
cd %1%
set TargetDir=%cd%

cd /d %~dp0..
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
echo "just add code to update registry"
exit /b

reg by hand

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{D9DA52E3-F96E-4C84-B153-C3B17C34F730}]

"DisplayIcon"="C:\\opt\\shibboleth-sp\\etc\\shibboleth-sp\\shib.ico,0"
"InstallSource"="C:\\Users\\Administrator\\Desktop\\"
"DisplayVersion"="4.0.0.0"
"Version"=dword:04000000
"VersionMinor"=dword:00000000
"VersionMajor"=dword:00000004
"UninstallString"="cmd /c pause"
"InstallLocation"=""

reg file called regkeys.txt



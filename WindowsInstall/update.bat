@echo off
setlocal

Rem probe for admin
net session 1> nul 2> nul
if %errorlevel% NEQ 0 (
   Echo Cannot update installation.  This command needs to be run with administrative rights.
   exit /b
)

Rem fail if parameters is not a distribution

Rem find kit root
cd %1%
set kit_root=%CD%

if not exist "dist\dist-bin\doupdate.bat" (
   echo "%1% is not a Shibboleth agent distribution"
   exit /b
)

Rem find root of install
cd %~dp0..\..
set install_path=%cd%

cd "%kit_root%\dist\dist-bin\"
cmd /c doupdate.bat "%install_path%"


rem @echo off

setlocal

rem fail if parameters is not a distribution

if not exist "%1%\dist\dist-bin\doupdate.bat" (
   echo "%1% is not a Shibboleth agent distribution"
   exit /b
)

rem find root of install
cd %~dp0..
set install_path=%cd%

cd "%1%\dist\dist-bin\"
cmd /c doupdate.bat "%install_path%"


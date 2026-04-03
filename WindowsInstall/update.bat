rem @echo off

setlocal

rem fail if parameters is not a distribution

rem find kit root
cd %1%
set kit_root=%CD%

if not exist "dist\dist-bin\doupdate.bat" (
   echo "%1% is not a Shibboleth agent distribution"
   exit /b
)

rem find root of install
cd %~dp0..\..
set install_path=%cd%

cd "%kit_root%\dist\dist-bin\"
cmd /c doupdate.bat "%install_path%"


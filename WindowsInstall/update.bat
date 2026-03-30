setlocal

rem fail if parameters is not a distribution

if (not exist %1%\dist-bin\doupdate.bat) (
   echo "%1% is not a Shibboleth agent distribution
   exit /b
)

rem find root of install
cd %dp0..
set path=%cd%

"%1%\dist-bin\doupdate.bat" "%path%"

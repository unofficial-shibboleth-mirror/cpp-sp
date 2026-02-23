setlocal

IF "%DevEnvDir%" == "" (
   Echo Visual Studio environment not loaded
   goto :done
)

cd /d %~dp0../../
set BUILD_HOME_DIR=%cd%

cd projects/VC22

rem Clean
del /s *.obj *.lib *.dll *.exe
del /s *.obj *.lib *.dll *.exe

REM Build all the DLLS and the msiversion executable

REM everything for x64
msbuild -m /property:Platform=x64;Configuration=release /MaxCPUCount Shibboleth.sln /t:iis;NativeLogMessages;MsiVersion;Apache

REM IIS only for Arm and x86
msbuild -m /property:Platform=arm64;Configuration=release /MaxCPUCount Shibboleth.sln /t:iis

REM IIS only for x86
msbuild -m /property:Platform=x86;Configuration=release /MaxCPUCount Shibboleth.sln /t:iis

FOR /F "delims= tokens=* USEBACKQ" %%F IN (`x64\release\MsiVersion.exe`) DO (
   SET MSIVERSION=%%F
)

echo MsiVersion derived to be 'MSIVERSION%'

cd ..\..\msi

REM Clean

dotnet clean installer.vcxproj /p:targetDir=%BUILD_HOME_DIR%\Projects\VC22\x64

REM and Build

dotnet build installer.vcxproj /p:targetPath=%BUILD_HOME_DIR%\Projects\VC22\x64\;Platform=x64;RootDir=%BUILD_HOME_DIR%;MsiVersion=%MSIVERSION%;Configuration=Release
move bin\x64\Release\Installer.msi %BUILD_HOME_DIR%\Projects\VC22\Agent.msi

:done

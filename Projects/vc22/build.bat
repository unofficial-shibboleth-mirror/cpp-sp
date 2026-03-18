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

if exist kit.zip (
    del kit.zip
)

if exist kit {
   rd /s /q kit
}


REM Build all the DLLS and the msiversion executable

REM everything for x64
msbuild -m /property:Platform=x64;Configuration=release /MaxCPUCount Shibboleth.sln /t:iis;NativeLogMessages;MsiVersion;Apache

REM IIS only for Arm64 and x86
msbuild -m /property:Platform=arm64;Configuration=release /MaxCPUCount Shibboleth.sln /t:iis
msbuild -m /property:Platform=x86;Configuration=release /MaxCPUCount Shibboleth.sln /t:iis

REM Build Kit.

mkdir kit
copy ..\..\WindowsInstall\install.bat kit\

mkdir kit\dist
x64\Release\MsiVersion.exe > kit\dist\Version.txt
echo 1 > kit\dist\InstallerVersion.txt

mkdir kit\dist\bin
copy ..\..\WindowsInstall\update.bat kit\dist\bin\

mkdir kit\dist\lib
copy x64\Release\iis_shib4.dll kit\dist\lib
copy x64\Release\mod_shib4.so kit\dist\lib
copy x64\Release\NativeLogMessages.dll kit\dist\lib
copy ARM64\Release\iis_shib4.dll kit\dist\lib\iis_shib4_arm64.dll
copy Release\iis_shib4.dll kit\dist\lib\iis_shib4_x86.dll

mkdir kit\dist\etc
copy ..\..\configs\agent.ini kit\dist\etc
copy ..\..\configs\handlers.ini kit\dist\etc
copy ..\..\configs\iis-config.ini kit\dist\etc
copy ..\..\configs\request-map.xml kit\dist\etc
copy ..\..\WindowsInstall\shib.ico kit\dist

mkdir kit\dist\dist-bin\
copy ..\..\WindowsInstall\doupdate.bat kit\dist-bin\bin\
copy ..\..\WindowsInstall\setreg.bat kit\dist-bin\bin\




tar -a -c -f kit.zip kit


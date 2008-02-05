@echo off
setlocal

if exist %~p0sp-key.pem goto protect
if exist %~p0sp-cert.pem goto protect

set DAYS=
set FQDN=
set TEMP_DOMAIN_NAME=
set PARAM=

:opt_start
set PARAM=%1
if not defined PARAM goto opt_end
if %1==-cn goto opt_fqdn
if %1==-years goto opt_years
goto usage
:opt_end

if not defined DAYS set DAYS=10
set /a DAYS=%DAYS%*365

if not defined FQDN goto guess_fqdn

:generate
set PATH=%~p0..\..\lib;%~p0..\..\bin
%~p0..\..\bin\openssl.exe req -x509 -days %DAYS% -newkey rsa:2048 -nodes -keyout %~p0sp-key.pem -out %~p0sp-cert.pem -subj /CN=%FQDN% -config %~p0openssl.cnf -extensions usr_cert -set_serial 0
exit /b

:protect
echo The files sp-key.pem and/or sp-cert.pem already exist!
exit /b

:opt_fqdn
set FQDN=%2
shift
shift
goto opt_start

:opt_years
set DAYS=%2
shift
shift
goto opt_start

:usage
echo usage: keygen [-cn cert common name to use] [-years years to issue cert]
exit /b

:guess_fqdn
for /F "tokens=2 delims=:" %%i in ('"ipconfig /all | findstr /c:"Primary DNS Suffix""') do set TEMP_DOMAIN_NAME=%%i
if defined TEMP_DOMAIN_NAME set FQDN=%TEMP_DOMAIN_NAME: =%
set TEMP_DOMAIN_NAME=
if defined USERDNSDOMAIN set FQDN=%USERDNSDOMAIN%

for /F %%i in ('hostname') do set HOST=%%i
if defined FQDN (set FQDN=%HOST%.%FQDN%) else (set FQDN=%HOST%)

echo >%FQDN%
for /F %%i in ('dir /b/l %FQDN%') do set FQDN=%%i
del %FQDN%
goto generate

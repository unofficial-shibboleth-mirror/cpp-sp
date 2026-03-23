REM 
REM Thanjs to tutorialreference,com

FOR /F "tokens=2 delims==" %%I IN ('WMIC OS GET LocalDateTime /VALUE') DO SET "dt=%%I"

SET YYYYMMDD="%dt:~0,8%"

echo ">>>  %YYYYMMDD%  <<<"

Set /a Version=0x11018864
Set /a MajorVersion="%VERSION% >> 24" > nul:
Set /a MinorVersion="(%VERSION% >> 16) & 0xFF" > nul:
echo "v = %VERSION%"
echo "mav = %MajorVERSION%"
echo "miv = %MinorVERSION%"

reg by hand
"DisplayIcon"="C:\\opt\\shibboleth-sp\\etc\\shibboleth-sp\\shib.ico,0"
"InstallSource"="C:\\Users\\Administrator\\Desktop\\"
"DisplayVersion"="4.0.0.0"
"Version"=dword:04000000
"VersionMinor"=dword:00000000
"VersionMajor"=dword:00000004
"UninstallString"="cmd /c pause"


reg file
====
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B034EFE0-0996-47A3-8296-6A7EAE948915}]
"DisplayName"="Shibboleth SP Windows Agent"
"Language"=dword:00000409
"NoModify"=dword:00000001
"URLUpdateInfo"="https://shibboleth.atlassian.net/wiki/spaces/spagent4"
"URLInfoAbout"="http://shibboleth.net/"
"EstimatedSize"=dword:000001234
"Size"=""
"Readme"=""
"Publisher"="Shibboleth Consortium"
"NoModify"=dword:00000001
"InstallLocation"=""
"HelpTelephone"=""
"HelpLink"=hex(2):68,00,74,00,74,00,70,00,73,00,3a,00,2f,00,2f,00,73,00,68,00,\
  69,00,62,00,62,00,6f,00,6c,00,65,00,74,00,68,00,2e,00,61,00,74,00,6c,00,61,\
  00,73,00,73,00,69,00,61,00,6e,00,2e,00,6e,00,65,00,74,00,2f,00,77,00,69,00,\
  6b,00,69,00,2f,00,73,00,70,00,61,00,63,00,65,00,73,00,2f,00,73,00,70,00,61,\
  00,67,00,65,00,6e,00,74,00,34,00,00,00
"Contact"="contact@shibboleth.net"
"Comments"=""
"AuthorizedCDFPrefix"=""



@echo off
setlocal

sc stop shibd_default
sc config shibd_default binPath= "@-INSTALLDIR-@\sbin\shibd.exe -stdout \"@-INSTALLDIR-@\var\log\shibboleth\stdout.log\" -stderr \"@-INSTALLDIR-@\var\log\shibboleth\stderr.log\""
ping 1.1.1.1 -n 1 -w 3000 > nul
sc start shibd_default

echo NOTE: You will need to manually adjust your IIS or Apache configuration to complete a switch to 32-bit use.
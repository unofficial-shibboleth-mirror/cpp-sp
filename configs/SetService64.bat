@echo off
setlocal
sc stop shibd_default
sc config shibd_default binPath= "@-INSTALLDIR-@\sbin64\shibd.exe -stdout \"@-INSTALLDIR-@\var\log\shibboleth\stdout.log\" -stderr \"@-INSTALLDIR-@\var\log\shibboleth\stderr.log\""
sc start shibd_default

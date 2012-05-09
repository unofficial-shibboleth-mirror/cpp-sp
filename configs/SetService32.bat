@echo off
setlocal
sc stop shibd_default
sc config shibd_default binPath= "@-INSTALLDIR-@\sbin\shibd.exe"
sc start shibd_default

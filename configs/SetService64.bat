@echo off
setlocal
sc stop shibd_default
sc config shibd_default binPath= "@-INSTALLDIR-@\sbin64\shibd.exe"
sc start shibd_default

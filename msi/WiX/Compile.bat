PATH=%PATH%;"C:\Program Files (x86)\Windows Installer XML v3.5\bin"

wixcop -indent:2 ShibbolethSP-exe-x64.wxs
candle ShibbolethSP-exe-x64.wxs

wixcop -indent:2 ShibbolethSP-registry-x64.wxs
candle ShibbolethSP-registry-x64.wxs

wixcop -indent:2 ShibbolethSP-noarch.wxs
candle ShibbolethSP-noarch.wxs

wixcop -indent:2 ShibbolethSP-exe-x86.wxs
candle ShibbolethSP-exe-x86.wxs

wixcop -indent:2 ShibbolethSP-registry-x86.wxs
candle ShibbolethSP-registry-x86.wxs

wixcop -indent:2 ShibbolethSP-gui.wxs
candle ShibbolethSP-gui.wxs

wixcop -indent:2 ShibbolethSP-update-dlg.wxs
candle ShibbolethSP-update-dlg.wxs

wixcop -indent:2 ShibbolethSP-install-dlg.wxs
candle ShibbolethSP-install-dlg.wxs

wixcop -indent:2 ShibbolethSP-main-x64.wxs
candle ShibbolethSP-main-x64.wxs
light -sw1055 -sice:ICE82 -o shibboleth-sp-2.5.0rc1-win64.msi ShibbolethSP-main-x64.wixobj ShibbolethSP-exe-x64.wixobj ShibbolethSP-registry-x64.wixobj  ShibbolethSP-noarch.wixobj ShibbolethSP-exe-x86.wixobj ShibbolethSP-registry-x86.wixobj ShibbolethSP-gui.wixobj ShibbolethSP-update-dlg.wixobj ShibbolethSP-install-dlg.wixobj -ext WixUtilExtension.dll -ext WixUIExtension -ext WixIISExtension

wixcop -indent:2 ShibbolethSP-main-x86.wxs
candle ShibbolethSP-main-x86.wxs
light -sw1055 -sice:ICE82 -o shibboleth-sp-2.5.0rc1-win32.msi ShibbolethSP-main-x86.wixobj ShibbolethSP-noarch.wixobj ShibbolethSP-exe-x86.wixobj ShibbolethSP-registry-x86.wixobj  ShibbolethSP-gui.wixobj ShibbolethSP-update-dlg.wixobj ShibbolethSP-install-dlg.wixobj -ext WixUtilExtension.dll -ext WixUIExtension  -ext WixIISExtension

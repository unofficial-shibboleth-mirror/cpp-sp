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

wixcop -indent:2 ShibbolethSP-shibd-dialog.wxs
candle ShibbolethSP-shibd-dialog.wxs

wixcop -indent:2 ShibbolethSP-iis-dialog.wxs
candle ShibbolethSP-iis-dialog.wxs

wixcop -indent:2 ShibbolethSP-main-x64.wxs
candle ShibbolethSP-main-x64.wxs
light -sw1055 -sice:ICE82 -o ShibbolethSP-main-x64.msi ShibbolethSP-main-x64.wixobj ShibbolethSP-exe-x64.wixobj ShibbolethSP-registry-x64.wixobj  ShibbolethSP-noarch.wixobj ShibbolethSP-exe-x86.wixobj ShibbolethSP-registry-x86.wixobj ShibbolethSP-shibd-dialog.wixobj ShibbolethSP-iis-dialog.wixobj ShibbolethSP-gui.wixobj -ext WixUtilExtension.dll -ext WixUIExtension

wixcop -indent:2 ShibbolethSP-main-x86.wxs
candle ShibbolethSP-main-x86.wxs
light -sw1055 -sice:ICE82 -o ShibbolethSP-main-x86.msi ShibbolethSP-main-x86.wixobj ShibbolethSP-noarch.wixobj ShibbolethSP-exe-x86.wixobj ShibbolethSP-registry-x86.wixobj ShibbolethSP-shibd-dialog.wixobj ShibbolethSP-iis-dialog.wixobj ShibbolethSP-gui.wixobj -ext WixUtilExtension.dll -ext WixUIExtension



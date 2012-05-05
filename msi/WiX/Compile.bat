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

wixcop -indent:2 ShibbolethSP-main-x64.wxs
candle ShibbolethSP-main-x64.wxs
light -sw1055 -sice:ICE82 -o ShibbolethSP-main-x64.msi ShibbolethSP-main-x64.wixobj ShibbolethSP-exe-x64.wixobj ShibbolethSP-registry-x64.wixobj  ShibbolethSP-noarch.wixobj ShibbolethSP-exe-x86.wixobj ShibbolethSP-registry-x86.wixobj



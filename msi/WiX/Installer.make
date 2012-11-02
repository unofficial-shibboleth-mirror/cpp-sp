all: all32 all64

all32: shibboleth-sp-$(ShibbolethVersion)-win32.msi

all64: shibboleth-sp-$(ShibbolethVersion)-win64.msi

clean32: 
	del *-x86.msi *-x86.wixobj *-x86.wixpdb *schemas.wixobj Shibboleth.wixlib

clean64: 
	del *-x64.wixobj *-x64.msi *-x64.wixpdb *schemas.wixobj Shibboleth.wixlib

clean: clean32 clean64

rebuild32: clean32 all32

rebuild64: clean64 all64

#
# MSI
#
shibboleth-sp-$(ShibbolethVersion)-win32.msi: ShibbolethSP-main-x86.wixobj Shibboleth.wixlib
	light -sw1055 -sice:ICE82 -o shibboleth-sp-$(ShibbolethVersion)-win32.msi ShibbolethSP-main-x86.wixobj Shibboleth.wixlib -ext WixUtilExtension.dll -ext WixUIExtension  -ext WixIISExtension
	del shibboleth-sp-$(ShibbolethVersion)-win64.msi

shibboleth-sp-$(ShibbolethVersion)-win64.msi: ShibbolethSP-main-x64.wixobj ShibbolethSP-exe-x64.wixobj ShibbolethSP-registry-x64.wixobj  Shibboleth.wixlib
	light -sw1055 -sice:ICE82 -o shibboleth-sp-$(ShibbolethVersion)-win64.msi ShibbolethSP-main-x64.wixobj ShibbolethSP-exe-x64.wixobj ShibbolethSP-registry-x64.wixobj  Shibboleth.wixlib -ext WixUtilExtension.dll -ext WixUIExtension -ext WixIISExtension

#
# Library
#
Shibboleth.wixlib: ShibbolethSP-noarch.wixobj ShibbolethSP-exe-x86.wixobj ShibbolethSP-registry-x86.wixobj  ShibbolethSP-gui.wixobj ShibbolethSP-update-dlg.wixobj ShibbolethSP-install-dlg.wixobj
	lit -pedantic -out  Shibboleth.wixlib ShibbolethSP-noarch.wixobj ShibbolethSP-exe-x86.wixobj ShibbolethSP-registry-x86.wixobj  ShibbolethSP-gui.wixobj ShibbolethSP-update-dlg.wixobj ShibbolethSP-install-dlg.wixobj

#
# Individual files
#
ShibbolethSP-exe-x64.wixobj: ShibbolethSP-exe-x64.wxs ..\..\x64\Release\shibd.exe ..\..\x64\Release\resolvertest.exe ..\..\x64\Release\mdquery.exe ..\..\x64\Release\adfs.so ..\..\x64\Release\adfs-lite.so ..\..\x64\Release\isapi_shib.dll ..\..\x64\Release\mod_shib_22.so ..\..\x64\Release\mod_shib_24.so ..\..\x64\Release\odbc-store.so ..\..\x64\Release\plugins.so ..\..\x64\Release\plugins-lite.so ..\..\x64\Release\shibauthorizer.exe ..\..\x64\Release\shibresponder.exe ..\..\x64\Debug\shibd.exe ..\..\x64\Debug\resolvertest.exe ..\..\x64\Debug\mdquery.exe ..\..\x64\Debug\adfs.so ..\..\x64\Debug\adfs-lite.so ..\..\x64\Debug\isapi_shib.dll ..\..\x64\Debug\mod_shib_22.so ..\..\x64\Debug\mod_shib_24.so ..\..\x64\Debug\odbc-store.so ..\..\x64\Debug\plugins.so ..\..\x64\Debug\plugins-lite.so ..\..\x64\Debug\shibauthorizer.exe ..\..\x64\Debug\shibresponder.exe
	wixcop -indent:2 ShibbolethSP-exe-x64.wxs
	candle -dSPBuildDirectory=$(SolutionDir).. ShibbolethSP-exe-x64.wxs

ShibbolethSP-registry-x64.wixobj: ShibbolethSP-registry-x64.wxs
	wixcop -indent:2 ShibbolethSP-registry-x64.wxs
	candle -dSPBuildDirectory=$(SolutionDir).. ShibbolethSP-registry-x64.wxs

ShibbolethSP-noarch.wixobj: ShibbolethSP-noarch.wxs ..\scripts\shib_install_isapi_filter.vbs-wix ..\scripts\shib_uninstall_isapi_filter.vbs-wix ..\scripts\shib_edit_config_files.vbs-wix
	wixcop -indent:2 ShibbolethSP-noarch.wxs
	candle -dSPBuildDirectory=$(SolutionDir).. ShibbolethSP-noarch.wxs

ShibbolethSP-exe-x86.wixobj: ShibbolethSP-exe-x86.wxs  ..\..\Release\shibd.exe ..\..\Release\resolvertest.exe ..\..\Release\mdquery.exe ..\..\Release\adfs.so ..\..\Release\adfs-lite.so ..\..\Release\isapi_shib.dll ..\..\Release\mod_shib_20.so ..\..\Release\mod_shib_22.so ..\..\Release\mod_shib_13.so ..\..\Release\mod_shib_24.so  ..\..\Release\nsapi_shib.dll ..\..\Release\odbc-store.so ..\..\Release\plugins.so ..\..\Release\plugins-lite.so ..\..\Release\shibauthorizer.exe ..\..\Release\shibresponder.exe ..\..\Debug\shibd.exe ..\..\Debug\resolvertest.exe ..\..\Debug\mdquery.exe ..\..\Debug\adfs.so ..\..\Debug\adfs-lite.so ..\..\Debug\isapi_shib.dll ..\..\Debug\mod_shib_13.so ..\..\Debug\mod_shib_20.so ..\..\Debug\mod_shib_22.so ..\..\Debug\mod_shib_24.so ..\..\Debug\nsapi_shib.dll ..\..\Debug\odbc-store.so ..\..\Debug\plugins.so ..\..\Debug\plugins-lite.so ..\..\Debug\shibauthorizer.exe ..\..\Debug\shibresponder.exe
	wixcop -indent:2 ShibbolethSP-exe-x86.wxs
	candle -dSPBuildDirectory=$(SolutionDir).. ShibbolethSP-exe-x86.wxs

ShibbolethSP-registry-x86.wixobj: ShibbolethSP-registry-x86.wxs
	wixcop -indent:2 ShibbolethSP-registry-x86.wxs
	candle -dSPBuildDirectory=$(SolutionDir).. ShibbolethSP-registry-x86.wxs

ShibbolethSP-gui.wixobj: ShibbolethSP-gui.wxs
	wixcop -indent:2 ShibbolethSP-gui.wxs
	candle -dSPBuildDirectory=$(SolutionDir).. ShibbolethSP-gui.wxs

ShibbolethSP-update-dlg.wixobj: ShibbolethSP-update-dlg.wxs
	wixcop -indent:2 ShibbolethSP-update-dlg.wxs
	candle ShibbolethSP-update-dlg.wxs

ShibbolethSP-install-dlg.wixobj: ShibbolethSP-install-dlg.wxs
	wixcop -indent:2 ShibbolethSP-install-dlg.wxs
	candle ShibbolethSP-install-dlg.wxs

ShibbolethSP-main-x64.wixobj: ShibbolethSP-main-x64.wxs MergeModules\Curl-x86.msm MergeModules\FastCGI-x86.msm MergeModules\Log4Shib-x86.msm MergeModules\OpenSAML-x86.msm MergeModules\OpenSAML-schemas.msm MergeModules\OpenSSL-x86.msm MergeModules\Shibboleth-x86.msm MergeModules\Shibboleth-schemas.msm MergeModules\Xerces-x86.msm MergeModules\XmlSec-x86.msm MergeModules\Zlib-x86.msm MergeModules\Curl-x64.msm MergeModules\FastCGI-x64.msm MergeModules\Log4Shib-x64.msm MergeModules\OpenSAML-x64.msm MergeModules\OpenSSL-x64.msm MergeModules\Shibboleth-x64.msm MergeModules\Xerces-x64.msm MergeModules\XmlSec-x64.msm MergeModules\Zlib-x64.msm
	wixcop -indent:2 ShibbolethSP-main-x64.wxs
	candle -dSPBuildDirectory=$(SolutionDir).. -dShibbolethVersion=$(ShibbolethVersion) -dShibbolethId64=$(ShibbolethId64) -dShibbolethUpgradeCode=$(ShibbolethUpgradeCode) ShibbolethSP-main-x64.wxs

ShibbolethSP-main-x86.wixobj: ShibbolethSP-main-x86.wxs MergeModules\Curl-x86.msm MergeModules\FastCGI-x86.msm MergeModules\Log4Shib-x86.msm MergeModules\OpenSAML-x86.msm MergeModules\OpenSAML-schemas.msm MergeModules\OpenSSL-x86.msm MergeModules\Shibboleth-x86.msm MergeModules\Shibboleth-schemas.msm MergeModules\Xerces-x86.msm MergeModules\XmlSec-x86.msm MergeModules\Zlib-x86.msm
	wixcop -indent:2 ShibbolethSP-main-x86.wxs
	candle -dSPBuildDirectory=$(SolutionDir).. -dShibbolethVersion=$(ShibbolethVersion) -dShibbolethId32=$(ShibbolethId32) -dShibbolethUpgradeCode=$(ShibbolethUpgradeCode) ShibbolethSP-main-x86.wxs

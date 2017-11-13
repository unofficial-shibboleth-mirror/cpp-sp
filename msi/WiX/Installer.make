LIGHT="C:\Program Files (x86)\WiX Toolset v3.11\bin\light"
LIT="C:\Program Files (x86)\WiX Toolset v3.11\bin\lit"
CANDLE="C:\Program Files (x86)\WiX Toolset v3.11\bin\candle"
WIXCOP="C:\Program Files (x86)\WiX Toolset v3.11\bin\wixcop"

APACHE_MODS_X64=..\..\Build\$(MsVCVersion)\x64\Debug\mod_shib_22.so ..\..\Build\$(MsVCVersion)\x64\Debug\mod_shib_24.so \
		..\..\Build\$(MsVCVersion)\x64\Release\mod_shib_22.so ..\..\Build\$(MsVCVersion)\x64\Release\mod_shib_24.so
APACHE_MODS_X86=..\..\Build\$(MsVCVersion)\Debug\mod_shib_13.so ..\..\Build\$(MsVCVersion)\Debug\mod_shib_20.so ..\..\Build\$(MsVCVersion)\Debug\mod_shib_22.so ..\..\Build\$(MsVCVersion)\Debug\mod_shib_24.so \
		..\..\Build\$(MsVCVersion)\Release\mod_shib_20.so ..\..\Build\$(MsVCVersion)\Release\mod_shib_22.so ..\..\Build\$(MsVCVersion)\Release\mod_shib_13.so ..\..\Build\$(MsVCVersion)\Release\mod_shib_24.so

!If "$(MsVCVersion)" != "vc14"
NSAPI_DLLS=..\..\Build\$(MsVCVersion)\Debug\nsapi_shib.dll ..\..\Build\$(MsVCVersion)\Release\nsapi_shib.dll
!Endif

all: all32 all64

all32: shibboleth-sp-$(ShibbolethVersion).$(ShibbolethPatchVersion)-win32.msi

all64: shibboleth-sp-$(ShibbolethVersion).$(ShibbolethPatchVersion)-win64.msi

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
shibboleth-sp-$(ShibbolethVersion).$(ShibbolethPatchVersion)-win32.msi: ShibbolethSP-main-x86.wixobj Shibboleth.wixlib
	$(LIGHT) -sw1055 -sice:ICE82 -o shibboleth-sp-$(ShibbolethVersion).$(ShibbolethPatchVersion)-win32.msi ShibbolethSP-main-x86.wixobj Shibboleth.wixlib -ext WixUtilExtension.dll -ext WixUIExtension  -ext WixIISExtension
	del shibboleth-sp-$(ShibbolethVersion)-win64.msi

shibboleth-sp-$(ShibbolethVersion).$(ShibbolethPatchVersion)-win64.msi: ShibbolethSP-main-x64.wixobj ShibbolethSP-exe-x64.wixobj ShibbolethSP-registry-x64.wixobj  Shibboleth.wixlib
	$(LIGHT) -sw1055 -sice:ICE82 -o shibboleth-sp-$(ShibbolethVersion).$(ShibbolethPatchVersion)-win64.msi ShibbolethSP-main-x64.wixobj ShibbolethSP-exe-x64.wixobj ShibbolethSP-registry-x64.wixobj  Shibboleth.wixlib -ext WixUtilExtension.dll -ext WixUIExtension -ext WixIISExtension

#
# Library
#
Shibboleth.wixlib: ShibbolethSP-noarch.wixobj ShibbolethSP-exe-x86.wixobj ShibbolethSP-registry-x86.wixobj  ShibbolethSP-gui.wixobj ShibbolethSP-update-dlg.wixobj ShibbolethSP-install-dlg.wixobj
	$(LIT) -pedantic -out  Shibboleth.wixlib ShibbolethSP-noarch.wixobj ShibbolethSP-exe-x86.wixobj ShibbolethSP-registry-x86.wixobj  ShibbolethSP-gui.wixobj ShibbolethSP-update-dlg.wixobj ShibbolethSP-install-dlg.wixobj

#
# Individual files
#
ShibbolethSP-exe-x64.wixobj: ShibbolethSP-exe-x64.wxs ..\..\Build\$(MsVCVersion)\x64\Release\shibd.exe ..\..\Build\$(MsVCVersion)\x64\Release\resolvertest.exe ..\..\Build\$(MsVCVersion)\x64\Release\mdquery.exe ..\..\Build\$(MsVCVersion)\x64\Release\adfs.so ..\..\Build\$(MsVCVersion)\x64\Release\adfs-lite.so ..\..\Build\$(MsVCVersion)\x64\Release\isapi_shib.dll ..\..\Build\$(MsVCVersion)\x64\Release\odbc-store.so ..\..\Build\$(MsVCVersion)\x64\Release\plugins.so ..\..\Build\$(MsVCVersion)\x64\Release\plugins-lite.so ..\..\Build\$(MsVCVersion)\x64\Release\shibauthorizer.exe ..\..\Build\$(MsVCVersion)\x64\Release\shibresponder.exe ..\..\Build\$(MsVCVersion)\x64\Debug\shibd.exe ..\..\Build\$(MsVCVersion)\x64\Debug\resolvertest.exe ..\..\Build\$(MsVCVersion)\x64\Debug\mdquery.exe ..\..\Build\$(MsVCVersion)\x64\Debug\adfs.so ..\..\Build\$(MsVCVersion)\x64\Debug\adfs-lite.so ..\..\Build\$(MsVCVersion)\x64\Debug\isapi_shib.dll $(APACHE_MODS_X64) ..\..\Build\$(MsVCVersion)\x64\Debug\odbc-store.so ..\..\Build\$(MsVCVersion)\x64\Debug\plugins.so ..\..\Build\$(MsVCVersion)\x64\Debug\plugins-lite.so ..\..\Build\$(MsVCVersion)\x64\Debug\shibauthorizer.exe ..\..\Build\$(MsVCVersion)\x64\Debug\shibresponder.exe
	$(WIXCOP) -indent:2 ShibbolethSP-exe-x64.wxs
	$(CANDLE) -dSPBuildDirectory=$(SolutionDir).. -dMsVCVersion=$(MsVCVersion) ShibbolethSP-exe-x64.wxs

ShibbolethSP-registry-x64.wixobj: ShibbolethSP-registry-x64.wxs
	$(WIXCOP) -indent:2 ShibbolethSP-registry-x64.wxs
	$(CANDLE) -dSPBuildDirectory=$(SolutionDir).. -dMsVCVersion=$(MsVCVersion) ShibbolethSP-registry-x64.wxs

ShibbolethSP-noarch.wixobj: ShibbolethSP-noarch.wxs ..\scripts\shib_install_isapi_filter.vbs-wix ..\scripts\shib_uninstall_isapi_filter.vbs-wix ..\scripts\shib_edit_config_files.vbs-wix
	$(WIXCOP) -indent:2 ShibbolethSP-noarch.wxs
	$(CANDLE) -dSPBuildDirectory=$(SolutionDir).. -dMsVCVersion=$(MsVCVersion) ShibbolethSP-noarch.wxs

ShibbolethSP-exe-x86.wixobj: ShibbolethSP-exe-x86.wxs  ..\..\Build\$(MsVCVersion)\Release\shibd.exe ..\..\Build\$(MsVCVersion)\Release\resolvertest.exe ..\..\Build\$(MsVCVersion)\Release\mdquery.exe ..\..\Build\$(MsVCVersion)\Release\adfs.so ..\..\Build\$(MsVCVersion)\Release\adfs-lite.so ..\..\Build\$(MsVCVersion)\Release\isapi_shib.dll ..\..\Build\$(MsVCVersion)\Release\odbc-store.so ..\..\Build\$(MsVCVersion)\Release\plugins.so ..\..\Build\$(MsVCVersion)\Release\plugins-lite.so ..\..\Build\$(MsVCVersion)\Release\shibauthorizer.exe ..\..\Build\$(MsVCVersion)\Release\shibresponder.exe ..\..\Build\$(MsVCVersion)\Debug\shibd.exe ..\..\Build\$(MsVCVersion)\Debug\resolvertest.exe ..\..\Build\$(MsVCVersion)\Debug\mdquery.exe ..\..\Build\$(MsVCVersion)\Debug\adfs.so ..\..\Build\$(MsVCVersion)\Debug\adfs-lite.so ..\..\Build\$(MsVCVersion)\Debug\isapi_shib.dll $(APACHE_MODE_X86) $(NSAPI_DLLS) ..\..\Build\$(MsVCVersion)\Debug\odbc-store.so ..\..\Build\$(MsVCVersion)\Debug\plugins.so ..\..\Build\$(MsVCVersion)\Debug\plugins-lite.so ..\..\Build\$(MsVCVersion)\Debug\shibauthorizer.exe ..\..\Build\$(MsVCVersion)\Debug\shibresponder.exe
	$(WIXCOP) -indent:2 ShibbolethSP-exe-x86.wxs
	$(CANDLE) -dSPBuildDirectory=$(SolutionDir).. -dMsVCVersion=$(MsVCVersion) ShibbolethSP-exe-x86.wxs

ShibbolethSP-registry-x86.wixobj: ShibbolethSP-registry-x86.wxs
	$(WIXCOP) -indent:2 ShibbolethSP-registry-x86.wxs
	$(CANDLE) -dSPBuildDirectory=$(SolutionDir).. -dMsVCVersion=$(MsVCVersion) ShibbolethSP-registry-x86.wxs

ShibbolethSP-gui.wixobj: ShibbolethSP-gui.wxs
	$(WIXCOP) -indent:2 ShibbolethSP-gui.wxs
	$(CANDLE) -dSPBuildDirectory=$(SolutionDir).. -dMsVCVersion=$(MsVCVersion) ShibbolethSP-gui.wxs

ShibbolethSP-update-dlg.wixobj: ShibbolethSP-update-dlg.wxs
	$(WIXCOP) -indent:2 ShibbolethSP-update-dlg.wxs
	$(CANDLE) ShibbolethSP-update-dlg.wxs

ShibbolethSP-install-dlg.wixobj: ShibbolethSP-install-dlg.wxs
	$(WIXCOP) -indent:2 ShibbolethSP-install-dlg.wxs
	$(CANDLE) ShibbolethSP-install-dlg.wxs

ShibbolethSP-main-x64.wixobj: ShibbolethSP-main-x64.wxs ShibbolethSP-properties.wxi ShibbolethSP-defs-x86.wxi MergeModules\Curl-x86.msm MergeModules\FastCGI-x86.msm MergeModules\Log4Shib-x86.msm MergeModules\OpenSAML-x86.msm MergeModules\OpenSAML-schemas.msm MergeModules\OpenSSL-x86.msm MergeModules\Shibboleth-x86.msm MergeModules\Shibboleth-schemas.msm MergeModules\Xerces-x86.msm MergeModules\XmlSec-x86.msm MergeModules\Zlib-x86.msm MergeModules\Curl-x64.msm MergeModules\FastCGI-x64.msm MergeModules\Log4Shib-x64.msm MergeModules\OpenSAML-x64.msm MergeModules\OpenSSL-x64.msm MergeModules\Shibboleth-x64.msm MergeModules\Xerces-x64.msm MergeModules\XmlSec-x64.msm MergeModules\Zlib-x64.msm
	$(WIXCOP) -indent:2 ShibbolethSP-main-x64.wxs
	$(CANDLE) -dSPBuildDirectory=$(SolutionDir).. -dShibbolethVersion=$(ShibbolethVersion) -dShibbolethPatchVersion=$(ShibbolethPatchVersion) -dShibbolethId64=$(ShibbolethId64) -dShibbolethUpgradeCode=$(ShibbolethUpgradeCode) -dMsVCVersion=$(MsVCVersion) ShibbolethSP-main-x64.wxs

ShibbolethSP-main-x86.wixobj: ShibbolethSP-main-x86.wxs ShibbolethSP-properties.wxi ShibbolethSP-defs-x86.wxi MergeModules\Curl-x86.msm MergeModules\FastCGI-x86.msm MergeModules\Log4Shib-x86.msm MergeModules\OpenSAML-x86.msm MergeModules\OpenSAML-schemas.msm MergeModules\OpenSSL-x86.msm MergeModules\Shibboleth-x86.msm MergeModules\Shibboleth-schemas.msm MergeModules\Xerces-x86.msm MergeModules\XmlSec-x86.msm MergeModules\Zlib-x86.msm
	$(WIXCOP) -indent:2 ShibbolethSP-main-x86.wxs
	$(CANDLE) -dSPBuildDirectory=$(SolutionDir).. -dShibbolethVersion=$(ShibbolethVersion) -dShibbolethPatchVersion=$(ShibbolethPatchVersion) -dShibbolethId32=$(ShibbolethId32) -dShibbolethUpgradeCode=$(ShibbolethUpgradeCode) -dMsVCVersion=$(MsVCVersion) ShibbolethSP-main-x86.wxs

!if "$(DEBUG_INSTALLER)" != ""
APACHE_MODS_X64=..\..\Build\$(MsVCVersion)\x64\Debug\mod_shib_22.so ..\..\Build\$(MsVCVersion)\x64\Debug\mod_shib_24.so \
		..\..\Build\$(MsVCVersion)\x64\Release\mod_shib_22.so ..\..\Build\$(MsVCVersion)\x64\Release\mod_shib_24.so

APACHE_MODS_X86=..\..\Build\$(MsVCVersion)\Debug\mod_shib_22.so ..\..\Build\$(MsVCVersion)\Debug\mod_shib_24.so \
		..\..\Build\$(MsVCVersion)\Release\mod_shib_22.so ..\..\Build\$(MsVCVersion)\Release\mod_shib_24.so
NSAPI_DLLS=..\..\Build\$(MsVCVersion)\Debug\nsapi_shib.dll ..\..\Build\$(MsVCVersion)\Release\nsapi_shib.dll
!else
APACHE_MODS_X64=..\..\Build\$(MsVCVersion)\x64\Release\mod_shib_22.so ..\..\Build\$(MsVCVersion)\x64\Release\mod_shib_24.so

APACHE_MODS_X86=..\..\Build\$(MsVCVersion)\Release\mod_shib_22.so ..\..\Build\$(MsVCVersion)\Release\mod_shib_24.so
NSAPI_DLLS=..\..\Build\$(MsVCVersion)\Release\nsapi_shib.dll
!endif

!If "$(MsVCVersion)" == "vc10"
!Error MSVC 10 not supported
!Endif

!If "$(CppMmDir)" == ""
CppMmDir=C:\Program Files (x86)\Common Files\Merge Modules
!else
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
	light -sw1055 -sice:ICE82 -o shibboleth-sp-$(ShibbolethVersion).$(ShibbolethPatchVersion)-win32.msi ShibbolethSP-main-x86.wixobj Shibboleth.wixlib -ext WixUtilExtension.dll -ext WixUIExtension  -ext WixIISExtension
	del shibboleth-sp-$(ShibbolethVersion)-win64.msi

shibboleth-sp-$(ShibbolethVersion).$(ShibbolethPatchVersion)-win64.msi: ShibbolethSP-main-x64.wixobj ShibbolethSP-exe-x64.wixobj ShibbolethSP-registry-x64.wixobj  Shibboleth.wixlib
	light -sw1055 -sice:ICE82 -o shibboleth-sp-$(ShibbolethVersion).$(ShibbolethPatchVersion)-win64.msi ShibbolethSP-main-x64.wixobj ShibbolethSP-exe-x64.wixobj ShibbolethSP-registry-x64.wixobj  Shibboleth.wixlib -ext WixUtilExtension.dll -ext WixUIExtension -ext WixIISExtension

#
# Library
#
Shibboleth.wixlib: ShibbolethSP-noarch.wixobj ShibbolethSP-exe-x86.wixobj ShibbolethSP-registry-x86.wixobj  ShibbolethSP-gui.wixobj ShibbolethSP-update-dlg.wixobj ShibbolethSP-install-dlg.wixobj
	lit -pedantic -out  Shibboleth.wixlib ShibbolethSP-noarch.wixobj ShibbolethSP-exe-x86.wixobj ShibbolethSP-registry-x86.wixobj  ShibbolethSP-gui.wixobj ShibbolethSP-update-dlg.wixobj ShibbolethSP-install-dlg.wixobj

#
# Individual files
#
ShibbolethSP-exe-x64.wixobj: ShibbolethSP-exe-x64.wxs ..\..\Build\$(MsVCVersion)\x64\Release\shibd.exe ..\..\Build\$(MsVCVersion)\x64\Release\resolvertest.exe ..\..\Build\$(MsVCVersion)\x64\Release\mdquery.exe ..\..\Build\$(MsVCVersion)\x64\Release\adfs.so ..\..\Build\$(MsVCVersion)\x64\Release\adfs-lite.so ..\..\Build\$(MsVCVersion)\x64\Release\isapi_shib.dll ..\..\Build\$(MsVCVersion)\x64\Release\iis7_shib.dll ..\..\Build\$(MsVCVersion)\x64\Release\odbc-store.so ..\..\Build\$(MsVCVersion)\x64\Release\plugins.so ..\..\Build\$(MsVCVersion)\x64\Release\plugins-lite.so $(FCGI_AUTH_RESP64) $(APACHE_MODS_X64)
	wixcop -indent:2 ShibbolethSP-exe-x64.wxs
	candle -dSPBuildDirectory=$(SolutionDir).. -dMsVCVersion=$(MsVCVersion) ShibbolethSP-exe-x64.wxs -dFCGI="$(FCGI_AUTH_RESP64)" -dBuildDebug=$(DebugInstaller)

ShibbolethSP-registry-x64.wixobj: ShibbolethSP-registry-x64.wxs
	wixcop -indent:2 ShibbolethSP-registry-x64.wxs
	candle -dSPBuildDirectory=$(SolutionDir).. -dMsVCVersion=$(MsVCVersion) ShibbolethSP-registry-x64.wxs -dBuildDebug=$(DebugInstaller)

ShibbolethSP-noarch.wixobj: ShibbolethSP-noarch.wxs  ..\scripts\shib_edit_config_files.vbs-wix
	wixcop -indent:2 ShibbolethSP-noarch.wxs
	candle -dSPBuildDirectory=$(SolutionDir).. -dMsVCVersion=$(MsVCVersion) ShibbolethSP-noarch.wxs -dBuildDebug=$(DebugInstaller)

ShibbolethSP-exe-x86.wixobj: ShibbolethSP-exe-x86.wxs  ..\..\Build\$(MsVCVersion)\Release\shibd.exe ..\..\Build\$(MsVCVersion)\Release\resolvertest.exe ..\..\Build\$(MsVCVersion)\Release\mdquery.exe ..\..\Build\$(MsVCVersion)\Release\adfs.so ..\..\Build\$(MsVCVersion)\Release\adfs-lite.so ..\..\Build\$(MsVCVersion)\Release\iis7_shib.dll ..\..\Build\$(MsVCVersion)\Release\isapi_shib.dll ..\..\Build\$(MsVCVersion)\Release\odbc-store.so ..\..\Build\$(MsVCVersion)\Release\plugins.so ..\..\Build\$(MsVCVersion)\Release\plugins-lite.so $(FCGI_AUTH_RESP86) $(APACHE_MODS_X86) $(NSAPI_DLLS)
	wixcop -indent:2 ShibbolethSP-exe-x86.wxs
	candle -dSPBuildDirectory=$(SolutionDir).. -dMsVCVersion=$(MsVCVersion) ShibbolethSP-exe-x86.wxs -dNSApi="$(NSAPI_DLLS)" -dFCGI="$(FCGI_AUTH_RESP86)" -dBuildDebug=$(DebugInstaller)

ShibbolethSP-registry-x86.wixobj: ShibbolethSP-registry-x86.wxs
	wixcop -indent:2 ShibbolethSP-registry-x86.wxs
	candle -dSPBuildDirectory=$(SolutionDir).. -dMsVCVersion=$(MsVCVersion) ShibbolethSP-registry-x86.wxs -dBuildDebug=$(DebugInstaller)

ShibbolethSP-gui.wixobj: ShibbolethSP-gui.wxs
	wixcop -indent:2 ShibbolethSP-gui.wxs
	candle -dSPBuildDirectory=$(SolutionDir).. -dMsVCVersion=$(MsVCVersion) ShibbolethSP-gui.wxs -dBuildDebug=$(DebugInstaller)

ShibbolethSP-update-dlg.wixobj: ShibbolethSP-update-dlg.wxs
	wixcop -indent:2 ShibbolethSP-update-dlg.wxs
	candle ShibbolethSP-update-dlg.wxs -dBuildDebug=$(DebugInstaller)

ShibbolethSP-install-dlg.wixobj: ShibbolethSP-install-dlg.wxs
	wixcop -indent:2 ShibbolethSP-install-dlg.wxs
	candle ShibbolethSP-install-dlg.wxs -dBuildDebug=$(DebugInstaller)

ShibbolethSP-main-x64.wixobj: ShibbolethSP-main-x64.wxs ShibbolethSP-properties.wxi ShibbolethSP-defs-x86.wxi MergeModules\Curl-x86.msm $(FCGI86) MergeModules\Log4Shib-x86.msm MergeModules\OpenSAML-x86.msm MergeModules\OpenSAML-schemas.msm MergeModules\OpenSSL-x86.msm MergeModules\Shibboleth-x86.msm MergeModules\Shibboleth-schemas.msm MergeModules\Xerces-x86.msm MergeModules\XmlSec-x86.msm MergeModules\Zlib-x86.msm MergeModules\Curl-x64.msm $(FCGI64) MergeModules\Log4Shib-x64.msm MergeModules\OpenSAML-x64.msm MergeModules\OpenSSL-x64.msm MergeModules\Shibboleth-x64.msm MergeModules\Xerces-x64.msm MergeModules\XmlSec-x64.msm MergeModules\Zlib-x64.msm
	wixcop -indent:2 ShibbolethSP-main-x64.wxs
	candle -dSPBuildDirectory=$(SolutionDir).. -dShibbolethVersion=$(ShibbolethVersion) -dShibbolethPatchVersion=$(ShibbolethPatchVersion) -dShibbolethId64=$(ShibbolethId64) -dShibbolethUpgradeCode=$(ShibbolethUpgradeCode) -dMsVCVersion=$(MsVCVersion) ShibbolethSP-main-x64.wxs -dFCGI="$(FCGI64)" -dNSApi="$(NSAPI_DLLS)" -dCppMmDir="$(CppMmDir)" -dCppVCVersion=$(CppVCVersion) -dBuildDebug=$(DebugInstaller)

ShibbolethSP-main-x86.wixobj: ShibbolethSP-main-x86.wxs ShibbolethSP-properties.wxi ShibbolethSP-defs-x86.wxi MergeModules\Curl-x86.msm $(FCGI86) MergeModules\Log4Shib-x86.msm MergeModules\OpenSAML-x86.msm MergeModules\OpenSAML-schemas.msm MergeModules\OpenSSL-x86.msm MergeModules\Shibboleth-x86.msm MergeModules\Shibboleth-schemas.msm MergeModules\Xerces-x86.msm MergeModules\XmlSec-x86.msm MergeModules\Zlib-x86.msm
	wixcop -indent:2 ShibbolethSP-main-x86.wxs
	candle -dSPBuildDirectory=$(SolutionDir).. -dShibbolethVersion=$(ShibbolethVersion) -dShibbolethPatchVersion=$(ShibbolethPatchVersion) -dShibbolethId32=$(ShibbolethId32) -dShibbolethUpgradeCode=$(ShibbolethUpgradeCode) -dMsVCVersion=$(MsVCVersion) ShibbolethSP-main-x86.wxs  -dFCGI="$(FCGI64)" -dNSApi="$(NSAPI_DLLS)"  -dCppMmDir="$(CppMmDir)" -dCppVCVersion=$(CppVCVersion) -dBuildDebug=$(DebugInstaller)

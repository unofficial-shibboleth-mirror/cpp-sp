all: all32 all64

all32: Curl-x86.msm Log4shib-x86.msm OpenSAML-x86.msm OpenSAML-schemas.msm\
	OpenSSL-x86.msm Shibboleth-x86.msm Shibboleth-schemas.msm Xerces-x86.msm\
	XmlSec-x86.msm Zlib-x86.msm

all64: Curl-x64.msm Log4shib-x64.msm OpenSAML-x64.msm OpenSAML-schemas.msm\
	OpenSSL-x64.msm Shibboleth-x64.msm Shibboleth-schemas.msm Xerces-x64.msm\
	XmlSec-x64.msm Zlib-x64.msm

clean32:
	del *-x86.msm *-x86.wixobj *-x86.wixpdb *schemas.wixobj *schemas.msm

clean64:
	del *-x64.wixobj *-x64.msm *-x64.wixpdb *schemas.wixobj *schemas.msm

clean: clean32 clean64

rebuild32: clean32 all32

rebuild64: clean64 all64

#
# CURL
#
Curl-x64.msm: Curl-x64.wixobj
	light Curl-x64.wixobj
	del ..\*64*.msi

Curl-x64.wixobj: Curl-x64.wxs
	wixcop -indent:2 Curl-x64.wxs
	candle Curl-x64.wxs -dBuildDirectory=$(BuildSP) -dCurlVersion=$(CurlVersion)\
			 -dShibbolethMsVersion=$(MsVCVersion)

Curl-x86.msm: Curl-x86.wixobj
	light Curl-x86.wixobj
	del ..\*32*.msi

Curl-x86.wixobj: Curl-x86.wxs
	wixcop -indent:2 Curl-x86.wxs
	candle Curl-x86.wxs -dBuildDirectory=$(BuildSP) -dCurlVersion=$(CurlVersion)\
			-dShibbolethMsVersion=$(MsVCVersion)

#
# FastCGI
#
FastCGI-x86.msm: FastCGI-x86.wixobj
    light FastCGI-x86.wixobj

FastCGI-x86.wixobj: FastCGI-x86.wxs\
			$(BuildSP)\fcgi-$(FastCGIVersion)-$(MsVCVersion)\Win32\Release\libfcgi.dll \
			$(BuildSP)\fcgi-$(FastCGIVersion)-$(MsVCVersion)\Win32\Debug\libfcgid.dll
	wixcop -indent:2 FastCGI-x86.wxs
	candle FastCGI-x86.wxs -dBuildDirectory=$(BuildSP) -dFastCGIVersion=$(FastCGIVersion)\
			-dShibbolethMsVersion=$(MsVCVersion)

FastCGI-x64.msm: FastCGI-x64.wixobj
	light FastCGI-x64.wixobj


FastCGI-x64.wixobj: FastCGI-x64.wxs\
					$(BuildSP)\fcgi-$(FastCGIVersion)-$(MsVCVersion)\Win32\x64\Release\libfcgi.dll
					$(BuildSP)\fcgi-$(FastCGIVersion)-$(MsVCVersion)\Win32\x64\Debug\libfcgid.dll
	wixcop -indent:2 FastCGI-x64.wxs
	candle FastCGI-x64.wxs -dBuildDirectory=$(BuildSP) -dFastCGIVersion=$(FastCGIVersion)\
					-dShibbolethMsVersion=$(MsVCVersion)

#
# Log 4 shib.  More complicated since it has a version and a file version (and hence 2 components per architecture)
#
Log4Shib-x64.msm: Log4Shib-x64.wixobj
	light Log4Shib-x64.wixobj
	del ..\*64*.msi

Log4Shib-x86.msm: Log4Shib-x86.wixobj
	light Log4Shib-x86.wixobj
	del ..\*32*.msi

Log4Shib-x86.wixobj: Log4Shib-x86.wxs\
			$(BuildSP)\$(log4shib)\ms$(MsVCVersion)\Debug\log4shib$(Log4ShibFileVersion)D.dll\
			$(BuildSP)\$(log4shib)\ms$(MsVCVersion)\Release\log4shib$(Log4ShibFileVersion).dll
	wixcop -indent:2 Log4Shib-x86.wxs
	candle Log4Shib-x86.wxs -dBuildDirectory=$(BuildSP) -dLog4ShibVersion=$(Log4ShibVersion) -dlog4shib=$(log4shib)\
							-dLog4ShibFileVersion=$(Log4ShibFileVersion)\
                            -dLog4ShibComponent32=$(Log4ShibComponent32) -dLog4ShibComponent32d=$(Log4ShibComponent32d)\
                            -dShibbolethMsVersion=$(MsVCVersion)

Log4Shib-x64.wixobj: Log4Shib-x64.wxs\
			$(BuildSP)\$(log4shib)\ms$(MsVCVersion)\x64\Debug\log4shib$(Log4ShibFileVersion)D.dll\
			$(BuildSP)\$(log4shib)\ms$(MsVCVersion)\x64\Release\log4shib$(Log4ShibFileVersion).dll
	wixcop -indent:2 Log4Shib-x64.wxs
	candle Log4Shib-x64.wxs -dBuildDirectory=$(BuildSP) -dLog4ShibVersion=$(Log4ShibVersion) -dLog4ShibFileVersion=$(Log4ShibFileVersion)\
                            -dlog4shib=$(log4shib)\
                            -dLog4ShibComponent64=$(Log4ShibComponent64) -dLog4ShibComponent64d=$(Log4ShibComponent64d) -dShibbolethMsVersion=$(MsVCVersion)

#
# OpenSAML
#
OpenSAML-x86.msm: OpenSAML-x86.wixobj
	light OpenSAML-x86.wixobj
	del ..\*32*.msi

OpenSAML-x64.msm: OpenSAML-x64.wixobj
	light OpenSAML-x64.wixobj
	del ..\*64*.msi

OpenSAML-x86.wixobj: OpenSAML-x86.wxs $(SolutionDir)..\cpp-xmltooling\Build\$(MsVCVersion)\Release\xmltooling$(XmlToolingFileVersion).dll\
                                      $(SolutionDir)..\cpp-xmltooling\Build\$(MsVCVersion)\Release\xmltooling-lite$(XmlToolingFileVersion).dll\
                                      $(SolutionDir)..\cpp-OpenSaml\Build\$(MsVCVersion)\Release\saml$(OpenSAMLFileVersion).dll\
                                      $(SolutionDir)..\cpp-xmltooling\Build\$(MsVCVersion)\Debug\xmltooling$(XmlToolingFileVersion)d.dll\
                                      $(SolutionDir)..\cpp-xmltooling\Build\$(MsVCVersion)\Debug\xmltooling-lite$(XmlToolingFileVersion)d.dll\
                                      $(SolutionDir)..\cpp-OpenSaml\Build\$(MsVCVersion)\Debug\saml$(OpenSAMLFileVersion)d.dll
	wixcop -indent:2 OpenSAML-x86.wxs
	candle OpenSAML-x86.wxs -dSPBuildDirectory=$(SolutionDir).. -dOpenSAMLVersion=$(OpenSAMLVersion) -dOpenSAMLFileVersion=$(OpenSAMLFileVersion)\
                            -dXmlToolingFileVersion=$(XmlToolingFileVersion) -dSamlComponent32=$(SamlComponent32)\
                            -dXMLToolingComponent32=$(XMLToolingComponent32) -dXMLToolingLiteComponent32=$(XMLToolingLiteComponent32)\
                            -dSamlComponent32d=$(SamlComponent32d) -dXMLToolingComponent32d=$(XMLToolingComponent32d) \
                            -dXMLToolingLiteComponent32d=$(XMLToolingLiteComponent32d) -dShibbolethMsVersion=$(MsVCVersion)

OpenSAML-x64.wixobj: OpenSAML-x64.wxs $(SolutionDir)..\cpp-xmltooling\Build\$(MsVCVersion)\x64\Release\xmltooling$(XmlToolingFileVersion).dll\
                                      $(SolutionDir)..\cpp-xmltooling\Build\$(MsVCVersion)\x64\Release\xmltooling-lite$(XmlToolingFileVersion).dll\
                                      $(SolutionDir)..\cpp-OpenSaml\Build\$(MsVCVersion)\x64\Release\saml$(OpenSAMLFileVersion).dll\
                                      $(SolutionDir)..\cpp-xmltooling\Build\$(MsVCVersion)\x64\Debug\xmltooling$(XmlToolingFileVersion)d.dll\
                                      $(SolutionDir)..\cpp-xmltooling\Build\$(MsVCVersion)\x64\Debug\xmltooling-lite$(XmlToolingFileVersion)d.dll\
                                      $(SolutionDir)..\cpp-OpenSaml\Build\$(MsVCVersion)\x64\Debug\saml$(OpenSAMLFileVersion)d.dll
	wixcop -indent:2 OpenSAML-x64.wxs
	candle OpenSAML-x64.wxs -dSPBuildDirectory=$(SolutionDir).. -dOpenSAMLVersion=$(OpenSAMLVersion) -dOpenSAMLFileVersion=$(OpenSAMLFileVersion)\
                            -dXmlToolingFileVersion=$(XmlToolingFileVersion) -dSamlComponent64=$(SamlComponent64)\
                            -dXMLToolingComponent64=$(XMLToolingComponent64) -dXMLToolingLiteComponent64=$(XMLToolingLiteComponent64)\
                            -dSamlComponent64d=$(SamlComponent64d) -dXMLToolingComponent64d=$(XMLToolingComponent64d)\
                            -dXMLToolingLiteComponent64d=$(XMLToolingLiteComponent64d)  -dShibbolethMsVersion=$(MsVCVersion)

OpenSAML-schemas.msm: OpenSAML-schemas.wixobj
	light OpenSAML-schemas.wixobj
	del ..\*.msi

OpenSAML-schemas.wixobj: OpenSAML-schemas.wxs
	wixcop -indent:2 OpenSAML-schemas.wxs
	candle OpenSAML-schemas.wxs -dSPBuildDirectory=$(SolutionDir).. -dOpenSAMLVersion=$(OpenSAMLVersion)

#
# OpenSSL
#
OpenSSL-x86.msm: OpenSSL-x86.wixobj
	light OpenSSL-x86.wixobj
	del ..\*32*.msi

OpenSSL-x64.msm: OpenSSL-x64.wixobj
	light OpenSSL-x64.wixobj
	del ..\*64*.msi

OpenSSL-x86.wixobj: OpenSSL-x86.wxs
	wixcop -indent:2 OpenSSL-x86.wxs
	candle OpenSSL-x86.wxs -dBuildDirectory=$(BuildSP) -dOpenSSLVersion=$(OpenSSLVersion) \
                           -dOpenSSLFileVersion=$(OpenSSLFileVersion) -dLibEay32Component=$(LibEay32Component) -dSSlEay32Component=$(SSlEay32Component)\
                           -dLibEay32Componentd=$(LibEay32Componentd) -dSSlEay32Componentd=$(SSlEay32Componentd) -dopenssl=$(openssl)

OpenSSL-x64.wixobj: OpenSSL-x64.wxs
	wixcop -indent:2 OpenSSL-x64.wxs
	candle OpenSSL-x64.wxs -dBuildDirectory=$(BuildSP) -dOpenSSLVersion=$(OpenSSLVersion) \
                           -dOpenSSLFileVersion=$(OpenSSLFileVersion) -dLibEay64Component=$(LibEay64Component)\
                           -dSSlEay64Component=$(SSlEay64Component) -dLibEay64Componentd=$(LibEay64Componentd) -dSSlEay64Componentd=$(SSlEay64Componentd)  -dopenssl=$(openssl)

#
# Shibboleth DLL
#
Shibboleth-x86.msm: Shibboleth-x86.wixobj
	light Shibboleth-x86.wixobj
	del ..\*32*.msi

Shibboleth-x64.msm: Shibboleth-x64.wixobj
	light Shibboleth-x64.wixobj
	del ..\*64*.msi

Shibboleth-x86.wixobj: Shibboleth-x86.wxs $(SolutionDir)Build\$(MsVCVersion)\Release\shibsp$(ShibbolethDllFileVersion).dll\
                                          $(SolutionDir)Build\$(MsVCVersion)\Release\shibsp-lite$(ShibbolethDllFileVersion).dll\
                                          $(SolutionDir)Build\$(MsVCVersion)\Debug\shibsp$(ShibbolethDllFileVersion)d.dll\
                                          $(SolutionDir)Build\$(MsVCVersion)\Debug\shibsp-lite$(ShibbolethDllFileVersion)d.dll
	wixcop -indent:2 Shibboleth-x86.wxs
	candle Shibboleth-x86.wxs -dSPBuildDirectory=$(SolutionDir) -dShibbolethMsVersion=$(MsVCVersion) -dShibbolethDllVersion=$(ShibbolethDllVersion)\
                              -dShibbolethDllFileVersion=$(ShibbolethDllFileVersion) -dShibDll32Component=$(ShibDll32Component)\
                              -dShibDllLite32Component=$(ShibDllLite32Component) -dShibDll32Componentd=$(ShibDll32Componentd)\
                              -dShibDllLite32Componentd=$(ShibDllLite32Componentd)

Shibboleth-x64.wixobj: Shibboleth-x64.wxs $(SolutionDir)Build\$(MsVCVersion)\x64\Release\shibsp$(ShibbolethDllFileVersion).dll\
                                          $(SolutionDir)Build\$(MsVCVersion)\x64\Release\shibsp-lite$(ShibbolethDllFileVersion).dll\
                                          $(SolutionDir)Build\$(MsVCVersion)\x64\Debug\shibsp$(ShibbolethDllFileVersion)d.dll\
                                          $(SolutionDir)Build\$(MsVCVersion)\x64\Debug\shibsp-lite$(ShibbolethDllFileVersion)d.dll
	wixcop -indent:2 Shibboleth-x64.wxs
	candle Shibboleth-x64.wxs -dSPBuildDirectory=$(SolutionDir) -dShibbolethMsVersion=$(MsVCVersion) -dShibbolethDllVersion=$(ShibbolethDllVersion)\
                              -dShibbolethDllFileVersion=$(ShibbolethDllFileVersion) -dShibDll64Component=$(ShibDll64Component)\
                              -dShibDllLite64Component=$(ShibDllLite64Component) -dShibDll64Componentd=$(ShibDll64Componentd)\
                              -dShibDllLite64Componentd=$(ShibDllLite64Componentd)

Shibboleth-schemas.msm: Shibboleth-schemas.wixobj
	light Shibboleth-schemas.wixobj

Shibboleth-schemas.wixobj: Shibboleth-schemas.wxs
	wixcop -indent:2 Shibboleth-schemas.wxs
	candle Shibboleth-schemas.wxs -dSPBuildDirectory=$(SolutionDir).. -dShibbolethDllVersion=$(ShibbolethDllVersion)


#
# Xerces
#
Xerces-x86.msm: Xerces-x86.wixobj
	light Xerces-x86.wixobj
	del ..\*32*.msi

Xerces-x64.msm: Xerces-x64.wixobj
	light Xerces-x64.wixobj
	del ..\*64*.msi

XercesDll32=$(BuildSP)$(Xerces)\Install32\$(MsVCVersion)\bin\xerces-c_$(XercesFileVersion).dll
XercesDebugDll32=$(BuildSP)$(Xerces)\Install32\$(MsVCVersion)\bin\xerces-c_$(XercesFileVersion)D.dll

Xerces-x86.wixobj: Xerces-x86.wxs $(XercesDll32) Xerces-x86.wxs $(XercesDebugDll32)
	wixcop -indent:2 Xerces-x86.wxs
	candle Xerces-x86.wxs -dBuildDirectory=$(BuildSP) -dXercesDll=$(XercesDll32) -dXercesDebugDll=$(XercesDebugDll32) \
						  -dXercesVersion=$(XercesVersion) -dXercesFileVersion=$(XercesFileVersion) \
                          -dXerces32Component=$(Xerces32Component) -dXerces32Componentd=$(Xerces32Componentd)\
                          -dShibbolethMsVersion=$(MsVCVersion) -dxerces=$(Xerces)

XercesDll64=$(BuildSP)$(Xerces)\Install64\$(MsVCVersion)\bin\xerces-c_$(XercesFileVersion).dll
XercesDebugDll64=$(BuildSP)$(Xerces)\Install64\$(MsVCVersion)\bin\xerces-c_$(XercesFileVersion)D.dll

Xerces-x64.wixobj: Xerces-x64.wxs $(XercesDll64) Xerces-x86.wxs $(XercesDebugDll64)
	wixcop -indent:2 Xerces-x64.wxs
	candle Xerces-x64.wxs -dBuildDirectory=$(BuildSP) -dXercesDll=$(XercesDll64) -dXercesDebugDll=$(XercesDebugDll64) \
						  -dXercesVersion=$(XercesVersion) -dXercesFileVersion=$(XercesFileVersion) \
						  -dXerces64Component=$(Xerces64Component) -dXerces64Componentd=$(Xerces64Componentd)\
                          -dShibbolethMsVersion=$(MsVCVersion)  -dxerces=$(Xerces)


#
# XmlSec
#
XmlSec-x86.msm: XmlSec-x86.wixobj
	light XmlSec-x86.wixobj
	del ..\*32*.msi

XmlSec-x64.msm: XmlSec-x64.wixobj
	light XmlSec-x64.wixobj
	del ..\*64*.msi

XmlSec-x86.wixobj: XmlSec-x86.wxs "$(BuildSP)\$(xmlsec)\Build\Win32\$(MsVCVersion)\Release Minimal\xsec_$(XmlSecFileVersion).dll"\
                                  "$(BuildSP)\$(xmlsec)\Build\Win32\$(MsVCVersion)\Release Minimal\c14n.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\Win32\$(MsVCVersion)\Release Minimal\checksig.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\Win32\$(MsVCVersion)\Release Minimal\cipher.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\Win32\$(MsVCVersion)\Release Minimal\siginf.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\Win32\$(MsVCVersion)\Release Minimal\templatesign.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\Win32\$(MsVCVersion)\Release Minimal\txfmout.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\Win32\$(MsVCVersion)\Debug Minimal\xsec_$(XmlSecFileVersion)D.dll"\
                                  "$(BuildSP)\$(xmlsec)\Build\Win32\$(MsVCVersion)\Debug Minimal\c14n.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\Win32\$(MsVCVersion)\Debug Minimal\checksig.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\Win32\$(MsVCVersion)\Debug Minimal\cipher.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\Win32\$(MsVCVersion)\Debug Minimal\siginf.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\Win32\$(MsVCVersion)\Debug Minimal\templatesign.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\Win32\$(MsVCVersion)\Debug Minimal\txfmout.exe"
	wixcop -indent:2 XmlSec-x86.wxs
	candle XmlSec-x86.wxs -dBuildDirectory=$(BuildSP) -dXmlSecVersion=$(XmlSecVersion) -dxmlsec=$(xmlsec) -dXmlSecFileVersion=$(XmlSecFileVersion)\
                          -dXmlSec32Component=$(XmlSec32Component) -dXmlSec32Componentd=$(XmlSec32Componentd) -dShibbolethMsVersion=$(MsVCVersion)

XmlSec-x64.wixobj: XmlSec-x64.wxs "$(BuildSP)\$(xmlsec)\Build\x64\$(MsVCVersion)\Release Minimal\xsec_$(XmlSecFileVersion).dll"\
                                  "$(BuildSP)\$(xmlsec)\Build\x64\$(MsVCVersion)\Release Minimal\c14n.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\x64\$(MsVCVersion)\Release Minimal\checksig.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\x64\$(MsVCVersion)\Release Minimal\cipher.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\x64\$(MsVCVersion)\Release Minimal\siginf.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\x64\$(MsVCVersion)\Release Minimal\templatesign.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\x64\$(MsVCVersion)\Release Minimal\txfmout.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\x64\$(MsVCVersion)\Debug Minimal\xsec_$(XmlSecFileVersion)D.dll"\
                                  "$(BuildSP)\$(xmlsec)\Build\x64\$(MsVCVersion)\Debug Minimal\c14n.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\x64\$(MsVCVersion)\Debug Minimal\checksig.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\x64\$(MsVCVersion)\Debug Minimal\cipher.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\x64\$(MsVCVersion)\Debug Minimal\siginf.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\x64\$(MsVCVersion)\Debug Minimal\templatesign.exe"\
                                  "$(BuildSP)\$(xmlsec)\Build\x64\$(MsVCVersion)\Debug Minimal\txfmout.exe"
	wixcop -indent:2 XmlSec-x64.wxs
	candle XmlSec-x64.wxs -dBuildDirectory=$(BuildSP) -dXmlSecVersion=$(XmlSecVersion) -dxmlsec=$(xmlsec) -dXmlSecFileVersion=$(XmlSecFileVersion)\
                          -dXmlSec64Component=$(XmlSec64Component) -dXmlSec64Componentd=$(XmlSec64Componentd) -dShibbolethMsVersion=$(MsVCVersion)

#
# ZLIB
#

zlib-x86.msm: zlib-x86.wixobj
	light zlib-x86.wixobj
	del ..\*32*.msi

zlib-x64.msm: zlib-x64.wixobj
	light zlib-x64.wixobj
	del ..\*64*.msi

zlib-x86.wixobj: zlib-x86.wxs $(BuildSP)\$(zlib)\Release\zlib$(ZlibFileVersion).dll \
                              $(BuildSP)\$(zlib)\Debug\zlib$(ZlibFileVersion)d.dll
	wixcop -indent:2 zlib-x86.wxs
	candle zlib-x86.wxs -dBuildDirectory=$(BuildSP) -dZlibVersion=$(ZlibVersion) -dZlibFileVersion=$(ZlibFileVersion) \
						-dZlib32Component=$(Zlib32Component) -dZlib32Componentd=$(Zlib32Componentd) -dzlib=$(zlib)

zlib-x64.wixobj: zlib-x64.wxs $(BuildSP)\$(zlib)\x64\Release\zlib$(ZlibFileVersion).dll\
                              $(BuildSP)\$(zlib)\x64\Debug\zlib$(ZlibFileVersion)d.dll
	wixcop -indent:2 zlib-x64.wxs
	candle zlib-x64.wxs -dBuildDirectory=$(BuildSP) -dZlibVersion=$(ZlibVersion) -dZlibFileVersion=$(ZlibFileVersion) \
                        -dZlib64Component=$(Zlib64Component) -dZlib64Componentd=$(Zlib64Componentd)  -dzlib=$(zlib)

#

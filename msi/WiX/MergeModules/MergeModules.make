all: all32 all64

all32: Curl-x86.msm FastCGI-x86.msm Log4shib-x86.msm OpenSAML-x86.msm OpenSAML-schemas.msm OpenSSL-x86.msm Shibboleth-x86.msm Shibboleth-schemas.msm Xerces-x86.msm XmlSec-x86.msm Zlib-x86.msm

all64: Curl-x64.msm FastCGI-x64.msm Log4shib-x64.msm OpenSAML-x64.msm OpenSAML-schemas.msm OpenSSL-x64.msm Shibboleth-x64.msm Shibboleth-schemas.msm Xerces-x64.msm XmlSec-x64.msm Zlib-x64.msm

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
	del ..\*.msi

Curl-x64.wixobj: Curl-x64.wxs $(BuildSP)\curl-$(CurlVersion)\lib\release-dll-ssl-dll-zlib-dll.x64\libcurl5.dll $(BuildSP)\curl-$(CurlVersion)\lib\debug-dll-ssl-dll-zlib-dll.x64\libcurl5d.dll
	wixcop -indent:2 Curl-x64.wxs 
	candle Curl-x64.wxs -dBuildDirectory=$(BuildSP) -dCurlVersion=$(CurlVersion)

Curl-x86.msm: Curl-x86.wixobj 
	light Curl-x86.wixobj
	del ..\*.msi

Curl-x86.wixobj: Curl-x86.wxs $(BuildSP)\curl-$(CurlVersion)\lib\release-dll-ssl-dll-zlib-dll\libcurl5.dll $(BuildSP)\curl-$(CurlVersion)\lib\debug-dll-ssl-dll-zlib-dll\libcurl5d.dll 
	wixcop -indent:2 Curl-x86.wxs 
	candle Curl-x86.wxs -dBuildDirectory=$(BuildSP) -dCurlVersion=$(CurlVersion)

#
# FastCGI
#
FastCGI-x86.msm: FastCGI-x86.wixobj 
	light FastCGI-x86.wixobj
	del ..\*.msi

FastCGI-x86.wixobj: FastCGI-x86.wxs $(BuildSP)\fcgi-$(FastCGIVersion)-VC10\Win32\Release\libfcgi.dll  $(BuildSP)\fcgi-$(FastCGIVersion)-VC10\Win32\Debug\libfcgid.dll 
	wixcop -indent:2 FastCGI-x86.wxs 
	candle FastCGI-x86.wxs -dBuildDirectory=$(BuildSP) -dFastCGIVersion=$(FastCGIVersion)

FastCGI-x64.msm: FastCGI-x64.wixobj 
	light FastCGI-x64.wixobj
	del ..\*.msi

FastCGI-x64.wixobj: FastCGI-x64.wxs $(BuildSP)\fcgi-$(FastCGIVersion)-VC10\Win32\x64\Release\libfcgi.dll  $(BuildSP)\fcgi-$(FastCGIVersion)-VC10\Win32\x64\Debug\libfcgid.dll
	wixcop -indent:2 FastCGI-x64.wxs 
	candle FastCGI-x64.wxs -dBuildDirectory=$(BuildSP) -dFastCGIVersion=$(FastCGIVersion)

#
# Log 4 shib.  More complicated since it has a version and a file version (and hence 2 components per architecture)
#
Log4Shib-x64.msm: Log4Shib-x64.wixobj
	light Log4Shib-x64.wixobj
	del ..\*.msi

Log4Shib-x86.msm: Log4Shib-x86.wixobj
	light Log4Shib-x86.wixobj
	del ..\*.msi

Log4Shib-x86.wixobj: Log4Shib-x86.wxs $(BuildSP)\log4shib-$(Log4ShibVersion)\msvc10\Debug\log4shib$(Log4ShibFileVersion)D.dll $(BuildSP)\log4shib-$(Log4ShibVersion)\msvc10\Release\log4shib$(Log4ShibFileVersion).dll
	wixcop -indent:2 Log4Shib-x86.wxs 
	candle Log4Shib-x86.wxs -dBuildDirectory=$(BuildSP) -dLog4ShibVersion=$(Log4ShibVersion) -dLog4ShibFileVersion=$(Log4ShibFileVersion) -dLog4ShibComponent32=$(Log4ShibComponent32) -dLog4ShibComponent32d=$(Log4ShibComponent32d)

Log4Shib-x64.wixobj: Log4Shib-x64.wxs $(BuildSP)\log4shib-$(Log4ShibVersion)\msvc10\x64\Debug\log4shib$(Log4ShibFileVersion)D.dll $(BuildSP)\log4shib-$(Log4ShibVersion)\msvc10\x64\Release\log4shib$(Log4ShibFileVersion).dll
	wixcop -indent:2 Log4Shib-x64.wxs 
	candle Log4Shib-x64.wxs -dBuildDirectory=$(BuildSP) -dLog4ShibVersion=$(Log4ShibVersion) -dLog4ShibFileVersion=$(Log4ShibFileVersion) -dLog4ShibComponent64=$(Log4ShibComponent64) -dLog4ShibComponent64d=$(Log4ShibComponent64d)

#
# OpenSAML
#
OpenSAML-x86.msm: OpenSAML-x86.wixobj
	light OpenSAML-x86.wixobj
	del ..\*.msi

OpenSAML-x64.msm: OpenSAML-x64.wixobj
	light OpenSAML-x64.wixobj
	del ..\*.msi

OpenSAML-x86.wixobj: OpenSAML-x86.wxs $(SolutionDir)..\cpp-xmltooling\Release\xmltooling$(XmlToolingFileVersion).dll  $(SolutionDir)..\cpp-xmltooling\Release\xmltooling-lite$(XmlToolingFileVersion).dll  $(SolutionDir)..\cpp-OpenSaml\Release\saml$(OpenSAMLFileVersion).dll $(SolutionDir)..\cpp-xmltooling\Debug\xmltooling$(XmlToolingFileVersion)d.dll  $(SolutionDir)..\cpp-xmltooling\Debug\xmltooling-lite$(XmlToolingFileVersion)d.dll  $(SolutionDir)..\cpp-OpenSaml\Debug\saml$(OpenSAMLFileVersion)d.dll
	wixcop -indent:2 OpenSAML-x86.wxs 
	candle OpenSAML-x86.wxs -dSPBuildDirectory=$(SolutionDir).. -dOpenSAMLVersion=$(OpenSAMLVersion) -dOpenSAMLFileVersion=$(OpenSAMLFileVersion) -dXmlToolingFileVersion=$(XmlToolingFileVersion) -dSamlComponent32=$(SamlComponent32) -dXMLToolingComponent32=$(XMLToolingComponent32) -dXMLToolingLiteComponent32=$(XMLToolingLiteComponent32) -dSamlComponent32d=$(SamlComponent32d) -dXMLToolingComponent32d=$(XMLToolingComponent32d) -dXMLToolingLiteComponent32d=$(XMLToolingLiteComponent32d)

OpenSAML-x64.wixobj: OpenSAML-x64.wxs $(SolutionDir)..\cpp-xmltooling\x64\Release\xmltooling$(XmlToolingFileVersion).dll  $(SolutionDir)..\cpp-xmltooling\x64\Release\xmltooling-lite$(XmlToolingFileVersion).dll  $(SolutionDir)..\cpp-OpenSaml\x64\Release\saml$(OpenSAMLFileVersion).dll $(SolutionDir)..\cpp-xmltooling\x64\Debug\xmltooling$(XmlToolingFileVersion)d.dll  $(SolutionDir)..\cpp-xmltooling\x64\Debug\xmltooling-lite$(XmlToolingFileVersion)d.dll  $(SolutionDir)..\cpp-OpenSaml\x64\Debug\saml$(OpenSAMLFileVersion)d.dll
	wixcop -indent:2 OpenSAML-x64.wxs 
	candle OpenSAML-x64.wxs -dSPBuildDirectory=$(SolutionDir).. -dOpenSAMLVersion=$(OpenSAMLVersion) -dOpenSAMLFileVersion=$(OpenSAMLFileVersion) -dXmlToolingFileVersion=$(XmlToolingFileVersion) -dSamlComponent64=$(SamlComponent64) -dXMLToolingComponent64=$(XMLToolingComponent64) -dXMLToolingLiteComponent64=$(XMLToolingLiteComponent64) -dSamlComponent64d=$(SamlComponent64d) -dXMLToolingComponent64d=$(XMLToolingComponent64d) -dXMLToolingLiteComponent64d=$(XMLToolingLiteComponent64d)

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
	del ..\*.msi

OpenSSL-x64.msm: OpenSSL-x64.wixobj
	light OpenSSL-x64.wixobj
	del ..\*.msi

OpenSSL-x86.wixobj: OpenSSL-x86.wxs  $(BuildSP)\openssl-$(OpenSSLDirVersion)\out32dll\libeay32_$(OpenSSLFileVersion).dll $(BuildSP)\openssl-$(OpenSSLDirVersion)\out32dll\ssleay32_$(OpenSSLFileVersion).dll $(BuildSP)\openssl-$(OpenSSLDirVersion)\out32dll\openssl.exe $(BuildSP)\openssl-$(OpenSSLDirVersion)\out32dll.dbg\libeay32_$(OpenSSLFileVersion)d.dll $(BuildSP)\openssl-$(OpenSSLDirVersion)\out32dll.dbg\ssleay32_$(OpenSSLFileVersion)d.dll $(BuildSP)\openssl-$(OpenSSLDirVersion)\out32dll.dbg\openssl.exe
	wixcop -indent:2 OpenSSL-x86.wxs 
	candle OpenSSL-x86.wxs -dBuildDirectory=$(BuildSP) -dOpenSSLVersion=$(OpenSSLVersion) -dOpenSSLDirVersion=$(OpenSSLDirVersion) -dOpenSSLFileVersion=$(OpenSSLFileVersion) -dLibEay32Component=$(LibEay32Component) -dSSlEay32Component=$(SSlEay32Component) -dLibEay32Componentd=$(LibEay32Componentd) -dSSlEay32Componentd=$(SSlEay32Componentd)

OpenSSL-x64.wixobj: OpenSSL-x64.wxs  $(BuildSP)\openssl-$(OpenSSLDirVersion)\out64dll\libeay32_$(OpenSSLFileVersion).dll $(BuildSP)\openssl-$(OpenSSLDirVersion)\out64dll\ssleay32_$(OpenSSLFileVersion).dll $(BuildSP)\openssl-$(OpenSSLDirVersion)\out64dll\openssl.exe $(BuildSP)\openssl-$(OpenSSLDirVersion)\out64dll.dbg\libeay32_$(OpenSSLFileVersion)d.dll $(BuildSP)\openssl-$(OpenSSLDirVersion)\out64dll.dbg\ssleay32_$(OpenSSLFileVersion)d.dll $(BuildSP)\openssl-$(OpenSSLDirVersion)\out64dll.dbg\openssl.exe
	wixcop -indent:2 OpenSSL-x64.wxs 
	candle OpenSSL-x64.wxs -dBuildDirectory=$(BuildSP) -dOpenSSLVersion=$(OpenSSLVersion) -dOpenSSLDirVersion=$(OpenSSLDirVersion) -dOpenSSLFileVersion=$(OpenSSLFileVersion) -dLibEay64Component=$(LibEay64Component) -dSSlEay64Component=$(SSlEay64Component) -dLibEay64Componentd=$(LibEay64Componentd) -dSSlEay64Componentd=$(SSlEay64Componentd)

#
# Shibboleth DLL
#
Shibboleth-x86.msm: Shibboleth-x86.wixobj
	light Shibboleth-x86.wixobj
	del ..\*.msi

Shibboleth-x64.msm: Shibboleth-x64.wixobj
	light Shibboleth-x64.wixobj
	del ..\*.msi

Shibboleth-x86.wixobj: Shibboleth-x86.wxs $(SolutionDir)\Release\shibsp$(ShibbolethDllFileVersion).dll $(SolutionDir)\Release\shibsp-lite$(ShibbolethDllFileVersion).dll $(SolutionDir)\Debug\shibsp$(ShibbolethDllFileVersion)d.dll $(SolutionDir)\Debug\shibsp-lite$(ShibbolethDllFileVersion)d.dll
	wixcop -indent:2 Shibboleth-x86.wxs 
	candle Shibboleth-x86.wxs -dSPBuildDirectory=$(SolutionDir).. -dShibbolethDllVersion=$(ShibbolethDllVersion) -dShibbolethDllFileVersion=$(ShibbolethDllFileVersion) -dShibDll32Component=$(ShibDll32Component) -dShibDllLite32Component=$(ShibDllLite32Component) -dShibDll32Componentd=$(ShibDll32Componentd) -dShibDllLite32Componentd=$(ShibDllLite32Componentd)

Shibboleth-x64.wixobj: Shibboleth-x64.wxs $(SolutionDir)\x64\Release\shibsp$(ShibbolethDllFileVersion).dll $(SolutionDir)\x64\Release\shibsp-lite$(ShibbolethDllFileVersion).dll $(SolutionDir)\x64\Debug\shibsp$(ShibbolethDllFileVersion)d.dll $(SolutionDir)\x64\Debug\shibsp-lite$(ShibbolethDllFileVersion)d.dll
	wixcop -indent:2 Shibboleth-x64.wxs 
	candle Shibboleth-x64.wxs -dSPBuildDirectory=$(SolutionDir).. -dShibbolethDllVersion=$(ShibbolethDllVersion) -dShibbolethDllFileVersion=$(ShibbolethDllFileVersion) -dShibDll64Component=$(ShibDll64Component) -dShibDllLite64Component=$(ShibDllLite64Component) -dShibDll64Componentd=$(ShibDll64Componentd) -dShibDllLite64Componentd=$(ShibDllLite64Componentd)

Shibboleth-schemas.msm: Shibboleth-schemas.wixobj
	light Shibboleth-schemas.wixobj
	del ..\*.msi

Shibboleth-schemas.wixobj: Shibboleth-schemas.wxs
	wixcop -indent:2 Shibboleth-schemas.wxs 
	candle Shibboleth-schemas.wxs -dSPBuildDirectory=$(SolutionDir).. -dShibbolethDllVersion=$(ShibbolethDllVersion) 


#
# Xerces
#
Xerces-x86.msm: Xerces-x86.wixobj
	light Xerces-x86.wixobj
	del ..\*.msi

Xerces-x64.msm: Xerces-x64.wixobj
	light Xerces-x64.wixobj
	del ..\*.msi

Xerces-x86.wixobj: Xerces-x86.wxs $(BuildSP)\xerces-c-$(XercesVersion)-x86-windows-vc-10.0\bin\xerces-c_$(XercesFileVersion).dll Xerces-x86.wxs $(BuildSP)\xerces-c-$(XercesVersion)-x86-windows-vc-10.0\bin\xerces-c_$(XercesFileVersion)D.dll
	wixcop -indent:2 Xerces-x86.wxs 
	candle Xerces-x86.wxs -dBuildDirectory=$(BuildSP) -dXercesVersion=$(XercesVersion) -dXercesFileVersion=$(XercesFileVersion) -dXerces32Component=$(Xerces32Component) -dXerces32Componentd=$(Xerces32Componentd)

Xerces-x64.wixobj: Xerces-x64.wxs $(BuildSP)\xerces-c-$(XercesVersion)-x86_64-windows-vc-10.0\bin\xerces-c_$(XercesFileVersion).dll Xerces-x86.wxs $(BuildSP)\xerces-c-$(XercesVersion)-x86_64-windows-vc-10.0\bin\xerces-c_$(XercesFileVersion)D.dll
	wixcop -indent:2 Xerces-x64.wxs 
	candle Xerces-x64.wxs -dBuildDirectory=$(BuildSP) -dXercesVersion=$(XercesVersion) -dXercesFileVersion=$(XercesFileVersion) -dXerces64Component=$(Xerces64Component) -dXerces64Componentd=$(Xerces64Componentd)


#
# XmlSec
#
XmlSec-x86.msm: XmlSec-x86.wixobj
	light XmlSec-x86.wixobj
	del ..\*.msi

XmlSec-x64.msm: XmlSec-x64.wixobj
	light XmlSec-x64.wixobj
	del ..\*.msi

XmlSec-x86.wixobj: XmlSec-x86.wxs "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\Win32\VC10\Release No Xalan\xsec_$(XmlSecFileVersion).dll" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\Win32\VC10\Release No Xalan\c14n.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\Win32\VC10\Release No Xalan\checksig.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\Win32\VC10\Release No Xalan\cipher.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\Win32\VC10\Release No Xalan\siginf.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\Win32\VC10\Release No Xalan\templatesign.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\Win32\VC10\Release No Xalan\txfmout.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\Win32\VC10\Debug No Xalan\xsec_$(XmlSecFileVersion)D.dll" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\Win32\VC10\Debug No Xalan\c14n.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\Win32\VC10\Debug No Xalan\checksig.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\Win32\VC10\Debug No Xalan\cipher.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\Win32\VC10\Debug No Xalan\siginf.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\Win32\VC10\Debug No Xalan\templatesign.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\Win32\VC10\Debug No Xalan\txfmout.exe" 
	wixcop -indent:2 XmlSec-x86.wxs 
	candle XmlSec-x86.wxs -dBuildDirectory=$(BuildSP) -dXmlSecVersion=$(XmlSecVersion) -dXmlSecFileVersion=$(XmlSecFileVersion) -dXmlSec32Component=$(XmlSec32Component) -dXmlSec32Componentd=$(XmlSec32Componentd)

XmlSec-x64.wixobj: XmlSec-x64.wxs "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\x64\VC10\Release No Xalan\xsec_$(XmlSecFileVersion).dll" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\x64\VC10\Release No Xalan\c14n.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\x64\VC10\Release No Xalan\checksig.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\x64\VC10\Release No Xalan\cipher.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\x64\VC10\Release No Xalan\siginf.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\x64\VC10\Release No Xalan\templatesign.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\x64\VC10\Release No Xalan\txfmout.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\x64\VC10\Debug No Xalan\xsec_$(XmlSecFileVersion)D.dll" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\x64\VC10\Debug No Xalan\c14n.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\x64\VC10\Debug No Xalan\checksig.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\x64\VC10\Debug No Xalan\cipher.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\x64\VC10\Debug No Xalan\siginf.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\x64\VC10\Debug No Xalan\templatesign.exe" "$(BuildSP)\xml-security-c-$(XmlSecVersion)\Build\x64\VC10\Debug No Xalan\txfmout.exe"
	wixcop -indent:2 XmlSec-x64.wxs 
	candle XmlSec-x64.wxs -dBuildDirectory=$(BuildSP) -dXmlSecVersion=$(XmlSecVersion) -dXmlSecFileVersion=$(XmlSecFileVersion) -dXmlSec64Component=$(XmlSec64Component) -dXmlSec64Componentd=$(XmlSec64Componentd)

#
# ZLIB
#

zlib-x86.msm: zlib-x86.wixobj
	light zlib-x86.wixobj
	del ..\*.msi

zlib-x64.msm: zlib-x64.wixobj
	light zlib-x64.wixobj
	del ..\*.msi

zlib-x86.wixobj: zlib-x86.wxs $(BuildSP)\zlib-$(ZlibVersion)\Release\zlib$(ZlibFileVersion).dll $(BuildSP)\zlib-$(ZlibVersion)\Debug\zlib$(ZlibFileVersion)d.dll
	wixcop -indent:2 zlib-x86.wxs 
	candle zlib-x86.wxs -dBuildDirectory=$(BuildSP) -dZlibVersion=$(ZlibVersion) -dZlibFileVersion=$(ZlibFileVersion) -dZlib32Component=$(Zlib32Component) -dZlib32Componentd=$(Zlib32Componentd)

zlib-x64.wixobj: zlib-x64.wxs $(BuildSP)\zlib-$(ZlibVersion)\x64\Release\zlib$(ZlibFileVersion).dll $(BuildSP)\zlib-$(ZlibVersion)\x64\Debug\zlib$(ZlibFileVersion)d.dll
	wixcop -indent:2 zlib-x64.wxs 
	candle zlib-x64.wxs -dBuildDirectory=$(BuildSP) -dZlibVersion=$(ZlibVersion) -dZlibFileVersion=$(ZlibFileVersion) -dZlib64Component=$(Zlib64Component) -dZlib64Componentd=$(Zlib64Componentd)

#

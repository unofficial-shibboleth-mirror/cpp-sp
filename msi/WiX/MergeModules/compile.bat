PATH=%PATH%;"C:\Program Files (x86)\Windows Installer XML v3.5\bin"

goto current
:current
 wixcop -indent:2 Curl-x86.wxs
 candle Curl-x86.wxs
 light  Curl-x86.wixobj
 smoke  Curl-x86.msm
 wixcop -indent:2 Curl-x64.wxs
 candle Curl-x64.wxs
 light  Curl-x64.wixobj
 smoke  Curl-x64.msm

 wixcop -indent:2 FastCGI-x86.wxs
 candle FastCGI-x86.wxs
 light  FastCGI-x86.wixobj
 smoke  FastCGI-x86.msm
  wixcop -indent:2 FastCGI-x64.wxs
 candle FastCGI-x64.wxs
 light  FastCGI-x64.wixobj
 smoke  FastCGI-x64.msm

wixcop -indent:2 Log4Shib-x86.wxs
 candle Log4Shib-x86.wxs
 light  Log4Shib-x86.wixobj
 smoke  Log4Shib-x86.msm
wixcop -indent:2 Log4Shib-x64.wxs
 candle Log4Shib-x64.wxs
 light  Log4Shib-x64.wixobj
 smoke  Log4Shib-x64.msm


wixcop -indent:2 OpenSAML-x86.wxs
 candle OpenSAML-x86.wxs
 light  OpenSAML-x86.wixobj 
 smoke  OpenSAML-x86.msm

wixcop -indent:2 OpenSAML-schemas.wxs
 candle OpenSAML-schemas.wxs
 light  OpenSAML-schemas.wixobj
 smoke  OpenSAML-schemas.msm

wixcop -indent:2 OpenSAML-x64.wxs
 candle OpenSAML-x64.wxs
 light  OpenSAML-x64.wixobj 
 smoke  OpenSAML-x64.msm


wixcop -indent:2 OpenSSL-x86.wxs
 candle OpenSSL-x86.wxs
 light  OpenSSL-x86.wixobj
 smoke  OpenSSL-x86.msm
wixcop -indent:2 OpenSSL-x64.wxs
 candle OpenSSL-x64.wxs
 light  OpenSSL-x64.wixobj
 smoke  OpenSSL-x64.msm

 wixcop -indent:2 Shibboleth-x86.wxs
 candle Shibboleth-x86.wxs
 light  Shibboleth-x86.wixobj
 smoke  Shibboleth-x86.msm

 wixcop -indent:2 Shibboleth-x64.wxs
 candle Shibboleth-x64.wxs
 light  Shibboleth-x64.wixobj
 smoke  Shibboleth-x64.msm

 wixcop -indent:2 Shibboleth-schemas.wxs
 candle Shibboleth-schemas.wxs
 light  Shibboleth-schemas.wixobj
 smoke  Shibboleth-schemas.msm

 wixcop -indent:2  Xerces-x86.wxs
 candle Xerces-x86.wxs
 light  Xerces-x86.wixobj
 smoke  Xerces-x86.msm

 wixcop -indent:2  Xerces-x64.wxs
 candle Xerces-x64.wxs
 light  Xerces-x64.wixobj
 smoke  Xerces-x64.msm

 wixcop -indent:2 XmlSec-x86.wxs
 candle XmlSec-x86.wxs
 light  XmlSec-x86.wixobj
 smoke  XmlSec-x86.msm

 wixcop -indent:2 XmlSec-x64.wxs
 candle XmlSec-x64.wxs
 light  XmlSec-x64.wixobj
 smoke  XmlSec-x64.msm

 wixcop -indent:2  Zlib-x86.wxs
 candle Zlib-x86.wxs
 light  Zlib-x86.wixobj
 smoke  Zlib-x86.msm

 wixcop -indent:2  Zlib-x64.wxs
 candle Zlib-x64.wxs
 light  Zlib-x64.wixobj
 smoke  Zlib-x64.msm

goto done
:done
candle tes.wxs
light tes.wixobj
smoke tes.msi

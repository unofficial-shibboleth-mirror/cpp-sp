var oArgs = WScript.Arguments;

if (oArgs.length < 2) {
    WScript.Echo("usage: cscript xslt.js xml xsl");
    WScript.Quit();
}

xslFile = oArgs(0);
xmlFile = oArgs(1);

var xsl = new ActiveXObject("MSXML2.DOMDocument");
var xml = new ActiveXObject("MSXML2.DOMDocument");

xml.validateOnParse = false;
xml.async = false;
xml.load(xmlFile);

if (xml.parseError.errorCode != 0)
    WScript.Echo("XML Parse Error: " + xml.parseError.reason);

xsl.async = false;
xsl.load(xslFile);

if (xsl.parseError.errorCode != 0)
    WScript.Echo("XSL Parse Error: " + xsl.parseError.reason);

try {
    WScript.Echo(xml.transformNode(xsl.documentElement));
}
catch(err) {
    WScript.Echo("Transformation Error: " + err.number + "*" + err.description);
}

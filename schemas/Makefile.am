AUTOMAKE_OPTIONS = foreign

pkgxmldir = $(datadir)/xml/@PACKAGE_NAME@

schemafiles = \
    shibboleth.xsd \
    shibboleth-metadata-1.0.xsd \
    shibboleth-3.0-native-sp-config.xsd \
    shibboleth-2.0-native-sp-config.xsd \
    shibboleth-2.0-native-sp-protocols.xsd \
    shibboleth-2.0-sp-notify.xsd \
    shibboleth-2.0-afp.xsd \
    shibboleth-2.0-afp-mf-basic.xsd \
    shibboleth-2.0-afp-mf-saml.xsd \
    shibboleth-2.0-attribute-map.xsd \
    WS-Trust.xsd \
    MetadataExchange.xsd \
    oasis-200401-wss-wssecurity-secext-1.0.xsd \
    oasis-200401-wss-wssecurity-utility-1.0.xsd \
    ws-addr.xsd \
    ws-authorization.xsd \
    ws-federation.xsd \
    ws-securitypolicy-1.2.xsd
    

pkgxml_DATA = \
	catalog.xml \
	$(schemafiles)

#
# Some of these need building
#
do-build-file:
	rm -f ${FILE}.tmp
	sed < ${srcdir}/${FILE}.in > ${FILE}.tmp \
	    -e 's:@-PKGXMLDIR-@:${pkgxmldir}:g'
	cmp -s ${FILE} ${FILE}.tmp || mv ${FILE}.tmp ${FILE}
	rm -f ${FILE}.tmp

catalog.xml: ${srcdir}/catalog.xml.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

CLEANFILES = catalog.xml

EXTRA_DIST = catalog.xml.in \
	$(schemafiles)

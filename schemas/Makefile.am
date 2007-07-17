## $Id$ 

AUTOMAKE_OPTIONS = foreign

pkgxmldir = $(datadir)/xml/@PACKAGE@

schemafiles = \
    shibboleth.xsd \
    shibboleth-metadata-1.0.xsd \
    shibboleth-2.0-native-sp-config.xsd \
    shibboleth-2.0-afp.xsd \
    shibboleth-2.0-afp-mf-basic.xsd \
    shibboleth-2.0-afp-mf-saml.xsd \
    shibboleth-2.0-attribute-map.xsd \
    shibboleth-2.0-sp-notify.xsd \
    metadata_v12_to_v13.xsl \
    metadata_v13_to_v12.xsl \
    trust_v13_to_v12.xsl

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

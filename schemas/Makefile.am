## $Id$ 

AUTOMAKE_OPTIONS = foreign

pkgxmldir = $(datadir)/xml/@PACKAGE@

pkgxml_DATA = \
	catalog.xml \
    shibboleth-metadata-1.0.xsd \
    shibboleth-targetconfig-1.0.xsd \
            cs-sstc-schema-assertion-01.xsd \
            cs-sstc-schema-protocol-01.xsd \
            cs-sstc-schema-assertion-1.1.xsd \
            cs-sstc-schema-protocol-1.1.xsd \
            soap-envelope.xsd \
            xmldsig-core-schema.xsd \
   			xenc-schema.xsd \
            xml.xsd \
            shibboleth.xsd \
            shibboleth-trust-1.0.xsd \
			saml-schema-assertion-2.0.xsd \
			saml-schema-metadata-2.0.xsd \
			metadata_v12_to_v11.xsl \
			metadata_v12_to_v13.xsl \
			metadata_v13_to_v12.xsl \
			trust_v12_to_v11.xsl \
			trust_v13_to_v12.xsl

#
# Some of these need building
#
do-build-file:
	rm -f ${FILE}.tmp
	sed < ${srcdir}/${FILE}.in > ${FILE}.tmp \
	    -e 's:@-PKGXMLDIR-@:${pkgxmldir}:'
	cmp -s ${FILE} ${FILE}.tmp || mv ${FILE}.tmp ${FILE}
	rm -f ${FILE}.tmp

catalog.xml: ${srcdir}/catalog.xml.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

CLEANFILES = catalog.xml

EXTRA_DIST =
	catalog.xml.in \
    shibboleth-metadata-1.0.xsd \
    shibboleth-targetconfig-1.0.xsd

## $Id$

AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I .

EXTRA_DIST = \
        schemas/cs-sstc-schema-assertion-01.xsd \
        schemas/cs-sstc-schema-protocol-01.xsd \
        schemas/soap-envelope.xsd \
        schemas/xmldsig-core-schema.xsd \
        schemas/xmldsig-filter2.xsd \
        schemas/xml.xsd \
	schemas/shibboleth.xsd \
	schemas/eduPerson.xsd \
	configs/accessError.html \
	configs/shar.logger \
	configs/shireError.html \
	configs/apache.config \
	configs/shibboleth.ini \
	configs/ca-bundle.crt \
	configs/shibboleth.logger \
	configs/rmError.html \
	configs/shire.logger \
        configs/AAP.xml \
	libtool.m4 acx_pthread.m4 acx_rpctest.m4

WANT_SUBDIRS = @WANT_SUBDIRS@

SUBDIRS = $(WANT_SUBDIRS)

DIST_SUBDIRS = oncrpc shib schemas configs shib-target eduPerson shar test \
	mod_shire mod_shibrm

dist-hook:
	cp ../*.txt ../*.html $(distdir)


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
	docs/CREDITS.txt \
	docs/INSTALL.txt \
	docs/LICENSE.txt \
	docs/NEWS.txt \
	docs/README.txt \
	docs/OPENSSL.LICENSE \
	docs/LOG4CPP.LICENSE \
	docs/CURL.LICENSE \
	docs/InQueue.html \
	docs/DEPLOY-GUIDE-ORIGIN.html \
	docs/DEPLOY-GUIDE-TARGET.html \
	libtool.m4 \
	acx_pthread.m4 \
	acx_rpctest.m4

WANT_SUBDIRS = @WANT_SUBDIRS@

SUBDIRS = $(WANT_SUBDIRS)

DIST_SUBDIRS = doc oncrpc shib schemas configs shib-target shar test \
	mod_shire mod_shibrm siterefresh


## $Id$ 

AUTOMAKE_OPTIONS = foreign

pkglogdir = ${localstatedir}/log/@PACKAGE@
shirelogdir = ${localstatedir}/log/httpd
pkgxmldir = $(datadir)/xml/@PACKAGE@
varrundir = $(localstatedir)/run
pkgsysconfdir = $(sysconfdir)/@PACKAGE@
pkgsysconf_DATA = \
	apache.config \
	apache2.config \
	inqueue.pem

# The config files are installed "special".  Unlike the entries in
# pkgsysconf_DATA, these files are installed as "foo.dist" and only
# installed as "foo" if "foo" does not already exist.  In other words,
# the config files will not overwrite existing versions.
BUILTCONFIGFILES = \
	shibboleth.xml \
	native.logger \
	shibd.logger \
	AAP.xml \
	IQ-metadata.xml \
	example-metadata.xml

# While BUILTCONFIGFILES are processed, these are not; so we should pull
# them from SRCDIR.
CONFIGFILES = \
	shibboleth.logger \
	accessError.html \
	rmError.html \
	sessionError.html \
	metadataError.html \
	sp-example.key \
	sp-example.crt

#
# Some of these need building
#
do-build-file:
	rm -f ${FILE}.tmp
	sed < ${srcdir}/${FILE}.in > ${FILE}.tmp \
	    -e 's:@-PREFIX-@:${prefix}:' \
	    -e 's:@-LIBEXECDIR-@:${libexecdir}:' \
	    -e 's:@-PKGSYSCONFDIR-@:${pkgsysconfdir}:' \
	    -e 's:@-PKGXMLDIR-@:${pkgxmldir}:' \
	    -e 's:@-PKGLOGDIR-@:${pkglogdir}:' \
	    -e 's:@-SHIRELOGDIR-@:${shirelogdir}:' \
	    -e 's:@-VARRUNDIR-@:${varrundir}:'
	cmp -s ${FILE} ${FILE}.tmp || mv ${FILE}.tmp ${FILE}
	rm -f ${FILE}.tmp

apache.config: ${srcdir}/apache.config.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

apache2.config: ${srcdir}/apache2.config.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

shibd.logger: ${srcdir}/shibd.logger.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

native.logger: ${srcdir}/native.logger.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

shibboleth.xml: ${srcdir}/shibboleth.xml.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

AAP.xml: ${srcdir}/AAP.xml.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

IQ-metadata.xml: ${srcdir}/IQ-metadata.xml.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

example-metadata.xml: ${srcdir}/example-metadata.xml.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

all-data-local: $(BUILTCONFIGFILES)

install-data-local:	all-data-local
	$(mkinstalldirs) $(DESTDIR)$(pkglogdir)
	$(mkinstalldirs) $(DESTDIR)$(shirelogdir)
	$(mkinstalldirs) $(DESTDIR)$(varrundir)
	$(mkinstalldirs) $(DESTDIR)$(pkgxmldir)
	$(mkinstalldirs) $(DESTDIR)$(prefix)/data
	$(mkinstalldirs) $(DESTDIR)$(pkgsysconfdir)
	for f in $(BUILTCONFIGFILES); do \
		if test ! -f $(DESTDIR)${pkgsysconfdir}/$$f; then \
			$(INSTALL_DATA) $$f $(DESTDIR)${pkgsysconfdir}; \
		fi; \
		$(INSTALL_DATA) $$f $(DESTDIR)${pkgsysconfdir}/$$f.dist; \
        done
	for f in $(CONFIGFILES); do \
		if test ! -f $(DESTDIR)${pkgsysconfdir}/$$f; then \
			$(INSTALL_DATA) $(srcdir)/$$f $(DESTDIR)${pkgsysconfdir}; \
		fi; \
		$(INSTALL_DATA) $(srcdir)/$$f $(DESTDIR)${pkgsysconfdir}/$$f.dist; \
        done

CLEANFILES = \
	apache.config \
	apache2.config \
	shibd.logger \
	native.logger \
	shibboleth.xml \
	AAP.xml \
	IQ-metadata.xml \
	example-metadata.xml

EXTRA_DIST = .cvsignore \
	shibboleth.xml.in \
	native.logger.in \
	shibd.logger.in \
	apache.config.in \
	apache2.config.in \
	shibboleth.logger \
	accessError.html \
	rmError.html \
	sessionError.html \
	metadataError.html \
	AAP.xml.in \
	IQ-metadata.xml.in \
	example-metadata.xml.in \
	inqueue.pem \
	sp-example.key \
	sp-example.crt

## $Id$ 

AUTOMAKE_OPTIONS = foreign

pkglogdir=${localstatedir}/log/@PACKAGE@
pkgxmldir = $(datadir)/xml/@PACKAGE@
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
	shire.logger \
	shar.logger \
	AAP.xml \
	IQ-sites.xml \
	IQ-trust.xml

# While BUILTCONFIGFILES are processed, these are not; so we should pull
# them from SRCDIR.
CONFIGFILES = \
	shibboleth.logger \
	accessError.html \
	rmError.html \
	shireError.html \
	shar.key \
	shar.crt

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
	    -e 's:@-PKGLOGDIR-@:${pkglogdir}:'
	cmp -s ${FILE} ${FILE}.tmp || mv ${FILE}.tmp ${FILE}
	rm -f ${FILE}.tmp

apache.config: ${srcdir}/apache.config.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

apache2.config: ${srcdir}/apache2.config.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

shar.logger: ${srcdir}/shar.logger.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

shire.logger: ${srcdir}/shire.logger.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

shibboleth.xml: ${srcdir}/shibboleth.xml.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

AAP.xml: ${srcdir}/AAP.xml.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

IQ-sites.xml: ${srcdir}/IQ-sites.xml.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

IQ-trust.xml: ${srcdir}/IQ-trust.xml.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

all-data-local: $(BUILTCONFIGFILES)

install-data-local:	all-data-local
	$(mkinstalldirs) $(DESTDIR)$(pkglogdir)
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
	shar.logger \
	shire.logger \
	shibboleth.xml \
	AAP.xml \
	IQ-sites.xml \
	IQ-trust.xml

EXTRA_DIST = .cvsignore \
	shibboleth.xml.in \
	shire.logger.in \
	shar.logger.in \
	apache.config.in \
	apache2.config.in \
	shibboleth.logger \
	accessError.html \
	rmError.html \
	shireError.html \
	AAP.xml.in \
	IQ-sites.xml.in \
	IQ-trust.xml.in \
	inqueue.pem \
	shar.key \
	shar.crt

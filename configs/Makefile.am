AUTOMAKE_OPTIONS = foreign

pkglibdir = ${libdir}/@PACKAGE_NAME@
pkgwebdir = $(datadir)/@PACKAGE_NAME@
pkgcachedir = $(localstatedir)/cache/@PACKAGE_NAME@
pkgsysconfdir = $(sysconfdir)/@PACKAGE_NAME@
pkgsysconf_DATA = \
	apache24.config

# While BUILTCONFIGFILES are processed, these are not; so we should pull
# them from SRCDIR.
CONFIGFILES = \
	attrChecker.html \
	agent.ini \
	handlers.ini \
	request-map.xml

#
# Some of these need building
#
do-build-file:
	rm -f ${FILE}.tmp
	sed < ${srcdir}/${FILE}.in > ${FILE}.tmp \
		-e 's:@-PREFIX-@:${prefix}:g' \
		-e 's:@-PKGLIBDIR-@:${pkglibdir}:g' \
		-e 's:@-PKGSYSCONFDIR-@:${pkgsysconfdir}:g' \
		-e 's:@-PKGWEBDIR-@:${pkgwebdir}:g' \
		-e 's:@-PKGCACHEDIR-@:${pkgcachedir}:g'
	cmp -s ${FILE} ${FILE}.tmp || mv ${FILE}.tmp ${FILE}
	rm -f ${FILE}.tmp

apache24.config: ${srcdir}/apache24.config.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

all-data-local: $(BUILTCONFIGFILES)

install-data-local:	all-data-local
	$(mkinstalldirs) $(DESTDIR)$(pkgcachedir)
	$(mkinstalldirs) $(DESTDIR)$(pkgcachedir)/sessions
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
	apache24.config

EXTRA_DIST = \
	apache24.config.in \
	iis-config.ini \
	$(CONFIGFILES)

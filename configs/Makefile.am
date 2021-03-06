AUTOMAKE_OPTIONS = foreign

pkglibdir = ${libdir}/@PACKAGE_NAME@
pkglogdir = ${localstatedir}/log/@PACKAGE_NAME@
pkgxmldir = $(datadir)/xml/@PACKAGE_NAME@
pkgwebdir = $(datadir)/@PACKAGE_NAME@
pkgrundir = $(localstatedir)/run/@PACKAGE_NAME@
pkgcachedir = $(localstatedir)/cache/@PACKAGE_NAME@
pkgsysconfdir = $(sysconfdir)/@PACKAGE_NAME@
pkgsysconf_DATA = \
	shibd-systemd \
	shibd-redhat \
	shibd-amazon \
	shibd-suse \
	shibd-debian \
	shibd-osx.plist \
	apache.config \
	apache2.config \
	apache22.config \
	apache24.config \
	keygen.sh \
	metagen.sh \
	seckeygen.sh

# The config files are installed "special".  Unlike the entries in
# pkgsysconf_DATA, these files are installed as "foo.dist" and only
# installed as "foo" if "foo" does not already exist.  In other words,
# the config files will not overwrite existing versions.
BUILTCONFIGFILES = \
	native.logger \
	shibd.logger

# While BUILTCONFIGFILES are processed, these are not; so we should pull
# them from SRCDIR.
CONFIGFILES = \
	shibboleth2.xml \
	attribute-map.xml \
	attribute-policy.xml \
	protocols.xml \
	security-policy.xml \
	example-metadata.xml \
	example-shibboleth2.xml \
	console.logger \
	native.logger \
	attrChecker.html \
	sessionError.html \
	metadataError.html \
	bindingTemplate.html \
	discoveryTemplate.html \
	postTemplate.html \
	localLogout.html \
	globalLogout.html \
	partialLogout.html \
	sslError.html

#
# Some of these need building
#
do-build-file:
	rm -f ${FILE}.tmp
	sed < ${srcdir}/${FILE}.in > ${FILE}.tmp \
		-e 's:@-PREFIX-@:${prefix}:g' \
		-e 's:@-PKGLIBDIR-@:${pkglibdir}:g' \
		-e 's:@-PKGSYSCONFDIR-@:${pkgsysconfdir}:g' \
		-e 's:@-PKGXMLDIR-@:${pkgxmldir}:g' \
		-e 's:@-PKGWEBDIR-@:${pkgwebdir}:g' \
		-e 's:@-PKGLOGDIR-@:${pkglogdir}:g' \
		-e 's:@-PKGRUNDIR-@:${pkgrundir}:g' \
		-e 's:@-PKGCACHEDIR-@:${pkgcachedir}:g'
	cmp -s ${FILE} ${FILE}.tmp || mv ${FILE}.tmp ${FILE}
	rm -f ${FILE}.tmp

apache.config: ${srcdir}/apache.config.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

apache2.config: ${srcdir}/apache2.config.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

apache22.config: ${srcdir}/apache22.config.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

apache24.config: ${srcdir}/apache24.config.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

shibd-systemd: ${srcdir}/shibd-systemd.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

shibd-redhat: ${srcdir}/shibd-redhat.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

shibd-amazon: ${srcdir}/shibd-amazon.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

shibd-suse: ${srcdir}/shibd-suse.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

shibd-debian: ${srcdir}/shibd-debian.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

shibd-osx.plist: ${srcdir}/shibd-osx.plist.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

shibd.logger: ${srcdir}/shibd.logger.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

all-data-local: $(BUILTCONFIGFILES)

install-data-local:	all-data-local
	$(mkinstalldirs) $(DESTDIR)$(pkglogdir)
	$(mkinstalldirs) $(DESTDIR)$(pkgrundir)
	$(mkinstalldirs) $(DESTDIR)$(pkgcachedir)
	$(mkinstalldirs) $(DESTDIR)$(pkgxmldir)
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

install-data-hook:
	chmod +x $(DESTDIR)$(pkgsysconfdir)/keygen.sh
	chmod +x $(DESTDIR)$(pkgsysconfdir)/seckeygen.sh
	chmod +x $(DESTDIR)$(pkgsysconfdir)/metagen.sh
	if test -z "$(NOKEYGEN)"; then \
		if test ! -f $(DESTDIR)$(pkgsysconfdir)/sp-key.pem; then \
			cd $(DESTDIR)$(pkgsysconfdir); \
			/bin/sh ./keygen.sh -b -n sp-signing ; \
			/bin/sh ./keygen.sh -b -n sp-encrypt ; \
		fi; \
	fi

CLEANFILES = \
	apache.config \
	apache2.config \
	apache22.config \
	apache24.config \
	shibd-systemd \
	shibd-redhat \
	shibd-amazon \
	shibd-suse \
	shibd-debian \
	shibd-osx.plist \
	shibd.logger

EXTRA_DIST = \
	shibd.logger.in \
	apache.config.in \
	apache2.config.in \
	apache22.config.in \
	apache24.config.in \
	shibd-systemd.in \
	shibd-redhat.in \
	shibd-amazon.in \
	shibd-suse.in \
	shibd-debian.in \
	shibd-osx.plist.in \
	keygen.bat \
	seckeygen.bat \
	keygen.sh \
	metagen.sh \
	seckeygen.sh \
	win-shibboleth2.xml \
	win-native.logger \
	$(CONFIGFILES)

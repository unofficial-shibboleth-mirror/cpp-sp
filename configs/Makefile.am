## $Id$ 

AUTOMAKE_OPTIONS = foreign

logdir=${localstatedir}/log/shibboleth
pkgsysconfdir = $(sysconfdir)/@PACKAGE@
pkgsysconf_DATA = \
	shar.key \
	shar.crt \
	apache.config \
	apache2.config \
	AAP.xml \
	IQ-sites.xml \
	IQ-trust.xml \
	inqueue.pem

# The config files are installed "special".  Unlike the entries in
# pkgsysconf_DATA, these files are installed as "foo.dist" and only
# installed as "foo" if "foo" does not already exist.  In other words,
# the config files will not overwrite existing versions.
CONFIGFILES = \
	shibboleth.xml \
	shibboleth.logger \
	shire.logger \
	shar.logger \
	accessError.html \
	rmError.html \
	shireError.html

#
# Some of these need building
#
do-build-file:
	rm -f ${FILE}.tmp
	sed < ${srcdir}/${FILE}.in > ${FILE}.tmp \
	    -e 's:@-PREFIX-@:${prefix}:' \
	    -e 's:@-LIBEXECDIR-@:${libexecdir}:' \
	    -e 's:@-PKGSYSCONFDIR-@:${pkgsysconfdir}:' \
	    -e 's:@-LOGDIR-@:${logdir}:'
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

all-data-local: $(CONFIGFILES)

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(logdir)
	$(mkinstalldirs) $(DESTDIR)$(prefix)/data
	$(mkinstalldirs) $(DESTDIR)$(pkgsysconfdir)
	for f in $(CONFIGFILES); do \
		if test ! -f $(DESTDIR)${pkgsysconfdir}/$$f; then \
			$(INSTALL_DATA) $$f $(DESTDIR)${pkgsysconfdir}; \
		fi; \
		$(INSTALL_DATA) $$f $(DESTDIR)${pkgsysconfdir}/$$f.dist; \
        done

CLEANFILES = \
	apache.config \
	apache2.config \
	shar.logger \
	shire.logger \
	shibboleth.xml

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
	AAP.xml \
	IQ-sites.xml \
	IQ-trust.xml \
	inqueue.pem \
	shar.key \
	shar.crt

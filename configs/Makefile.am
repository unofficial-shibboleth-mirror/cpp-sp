## $Id$ 

AUTOMAKE_OPTIONS = foreign

logdir=${pkgsysconfdir}
pkgsysconfdir = $(sysconfdir)/@PACKAGE@
pkgsysconf_DATA = \
	shibboleth.ini \
	shibboleth.logger \
	shire.logger \
	shar.logger \
	apache.config \
	apache2.config \
	accessError.html \
	rmError.html \
	shireError.html \
	AAP.xml \
	sites.xml \
	trust.xml \
	creds.xml

#
# Some of these need building
#
do-build-file:
	rm -f ${FILE}.tmp
	sed < ${FILE}.in > ${FILE}.tmp \
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

shibboleth.ini: ${srcdir}/shibboleth.ini.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

creds.xml: ${srcdir}/creds.xml.in Makefile ${top_builddir}/config.status
	$(MAKE) do-build-file FILE=$@

CLEANFILES = \
	apache.config \
	apache2.config \
	shar.logger \
	shire.logger \
	shibboleth.ini \
	creds.xml

EXTRA_DIST = .cvsignore \
	shibboleth.ini.in \
	shire.logger.in \
	shar.logger.in \
	apache.config.in \
	apache2.config.in \
	shibboleth.logger \
	accessError.html \
	rmError.html \
	shireError.html \
	AAP.xml \
	sites.xml \
	trust.xml \
	creds.xml.in

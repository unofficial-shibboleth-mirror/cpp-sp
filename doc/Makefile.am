AUTOMAKE_OPTIONS = foreign

pkgdocdir = $(datadir)/doc/@PACKAGE_NAME@-@PACKAGE_VERSION@

install-data-hook:
	if test -d api ; then \
		cp -r api $(DESTDIR)$(pkgdocdir); \
	fi;

docfiles = \
	CREDITS.txt \
	LICENSE.txt \
	NOTICE.txt \
	README.txt \
	RELEASE.txt \
	FASTCGI.LICENSE

pkgdoc_DATA = $(docfiles)

EXTRA_DIST = $(docfiles)

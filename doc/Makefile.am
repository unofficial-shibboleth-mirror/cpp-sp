AUTOMAKE_OPTIONS = foreign

pkgdocdir = $(datadir)/doc/@PACKAGE@-@PACKAGE_VERSION@
pkgwebdir = $(datadir)/@PACKAGE@

install-data-hook:
	if test -d api ; then \
		cp -r api $(DESTDIR)$(pkgdocdir); \
		rm -rf `find $(DESTDIR)$(pkgdocdir)/api -name .svn`; \
	fi;

docfiles = \
	CREDITS.txt \
	LICENSE.txt \
	NOTICE.txt \
	README.txt \
	RELEASE.txt \
	FASTCGI.LICENSE \
	OPENSSL.LICENSE \
	LOG4CPP.LICENSE

webfiles = main.css logo.jpg

pkgdoc_DATA = $(docfiles)

pkgweb_DATA = $(webfiles)

EXTRA_DIST = $(docfiles) $(webfiles) api

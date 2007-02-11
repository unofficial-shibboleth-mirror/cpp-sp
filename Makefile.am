AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I .

EXTRA_DIST = \
	schemas doc isapi_shib isapi_shib_gui \
	Shibboleth.sln libtool.m4 acx_pthread.m4 acx_rpctest.m4 depcomp \
	config_win32.h shibtest/shibtest.vcproj \
	shibboleth.spec.in shibboleth.spec pkginfo.in pkginfo checkinstall

dist-hook:
	rm -rf `find $(distdir)/schemas -name Makefile`
	rm -rf `find $(distdir)/configs -name Makefile`
	rm -rf `find $(distdir)/doc -name Makefile`

WANT_SUBDIRS = @WANT_SUBDIRS@

SUBDIRS = $(WANT_SUBDIRS)

DIST_SUBDIRS = doc schemas configs shibsp shibd test \
	apache siterefresh odbc-store nsapi_shib selinux

all-local: shibboleth.spec pkginfo

shibboleth.spec: shibboleth.spec.in Makefile
	rm -f $@.tmp
	sed < $< > $@.tmp \
	    -e 's:@-VERSION-@:${VERSION}:'
	mv $@.tmp $@

pkginfo: pkginfo.in Makefile
	rm -f $@.tmp
	sed < $< > $@.tmp \
	    -e 's:@-VERSION-@:${VERSION}:'
	mv $@.tmp $@

DISTCLEANFILES = shibboleth.spec pkginfo

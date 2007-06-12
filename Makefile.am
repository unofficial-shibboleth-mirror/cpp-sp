AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I .

EXTRA_DIST = \
	isapi_shib isapi_shib_gui \
	Shibboleth.sln libtool.m4 acx_pthread.m4 depcomp \
	config_win32.h shibboleth.spec.in shibboleth.spec pkginfo.in pkginfo checkinstall

dist-hook:
	rm -rf `find $(distdir)/configs -name Makefile`

WANT_SUBDIRS = @WANT_SUBDIRS@

SUBDIRS = $(WANT_SUBDIRS)

DIST_SUBDIRS = doc schemas configs shibsp shibd util apache nsapi_shib selinux

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

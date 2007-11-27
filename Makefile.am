AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I .

EXTRA_DIST = \
	isapi_shib \
	Shibboleth.dsw libtool.m4 acx_pthread.m4 acx_rpctest.m4 depcomp \
	config_win32.h posttest/posttest.dsp shibtest/shibtest.dsp \
	shibboleth.spec.in shibboleth.spec pkginfo.in pkginfo depend postinstall

WANT_SUBDIRS = @WANT_SUBDIRS@

SUBDIRS = $(WANT_SUBDIRS)

DIST_SUBDIRS = adfs doc oncrpc shib schemas configs shib-target shar test \
	apache fastcgi siterefresh shib-mysql-ccache xmlproviders nsapi_shib selinux

all-local: shibboleth.spec pkginfo

dist-hook:
	rm -rf `find $(distdir)/isapi_shib -name .svn`

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

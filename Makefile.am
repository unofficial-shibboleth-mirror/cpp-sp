AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I .

EXTRA_DIST = \
	schemas doc isapi_shib isapi_shib_gui \
	Shibboleth.dsw libtool.m4 acx_pthread.m4 acx_rpctest.m4 depcomp config_win32.h \
    posttest/posttest.dsp \
    shibtest/shibtest.dsp

dist-hook:
	rm -rf `find $(distdir)/schemas -name CVS`
	rm -rf `find $(distdir)/schemas -name Makefile`
	rm -rf `find $(distdir)/configs -name CVS`
	rm -rf `find $(distdir)/configs -name Makefile`
	rm -rf `find $(distdir)/doc -name CVS`
	rm -rf `find $(distdir)/doc -name Makefile`
	rm -rf `find $(distdir)/isapi_shib -name CVS`

WANT_SUBDIRS = @WANT_SUBDIRS@

SUBDIRS = $(WANT_SUBDIRS)

DIST_SUBDIRS = doc oncrpc shib schemas configs shib-target shar test \
	apache siterefresh shib-mysql-ccache xmlproviders

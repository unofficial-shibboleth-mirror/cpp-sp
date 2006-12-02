## $Id$

AUTOMAKE_OPTIONS = foreign

pkgsysconfdir = $(sysconfdir)/@PACKAGE@
pkgxmldir = $(datadir)/xml/@PACKAGE@

lib_LTLIBRARIES = libshib-target.la

if USE_OUR_ONCRPC
libshib_target_la_LIBADD = ${top_builddir}/oncrpc/liboncrpc.la
AM_CFLAGS = -I${top_srcdir}/oncrpc
AM_CXXFLAGS = -I${top_srcdir}/oncrpc
endif

libshib_targetdir = $(includedir)/shib-target
libshib_target_HEADERS = shib-target.h shib-paths.h hresult.h ddf.h
noinst_HEADERS = internal.h SocketListener.h

libshib_target_la_SOURCES = \
	ArtifactMapper.cpp \
	CommonDomainCookie.cpp \
	ddf.cpp \
	IListener.cpp \
	SocketListener.cpp \
    ShibHTTPHook.cpp \
	shib-ccache.cpp \
	shib-config.cpp \
	shib-handlers.cpp \
	shib-ini.cpp \
	shib-mlp.cpp \
	shib-target.cpp \
	TCPListener.cpp \
	UnixListener.cpp \
	XML.cpp \
	XMLRequestMapper.cpp

# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
libshib_target_la_LDFLAGS = -version-info 7:0:0



shib-paths.h: ${srcdir}/shib-paths.h.in Makefile ${top_builddir}/config.status
	rm -f $@.tmp
	sed < ${srcdir}/$@.in > $@.tmp \
	    -e 's:@-PKGSYSCONFDIR-@:${pkgsysconfdir}:' \
	    -e 's:@-PKGXMLDIR-@:${pkgxmldir}:'
	cmp -s $@ $@.tmp || mv $@.tmp $@
	rm -f $@.tmp

install-exec-hook:
	for la in $(lib_LTLIBRARIES) ; do rm -f $(DESTDIR)$(libdir)/$$la ; done

EXTRA_DIST = shibtarget.vcproj shib-paths.h.in resource.h shib-target.rc
BUILT_SOURCES = shib-paths.h

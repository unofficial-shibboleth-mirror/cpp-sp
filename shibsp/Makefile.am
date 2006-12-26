AUTOMAKE_OPTIONS = foreign

pkgsysconfdir = $(sysconfdir)/@PACKAGE@
xmldir = $(datadir)/xml

lib_LTLIBRARIES = libshibsp.la

libshibspincludedir = $(includedir)/shibsp

libshibspinclude_HEADERS = \
	base.h \
	ddf.h \
	DOMPropertySet.h \
	exceptions.h \
	ListenerService.h \
	paths.h \
	PropertySet.h \
	version.h \
	SocketListener.h \
	SPConfig.h

noinst_HEADERS = \
	internal.h

libshibsp_la_SOURCES = \
	ddf.cpp \
	DOMPropertySet.cpp \
	ListenerService.cpp \
	SocketListener.cpp \
	TCPListener.cpp \
	UnixListener.cpp \
	SPConfig.cpp

# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
libshibsp_la_LDFLAGS = -version-info 1:0:0

paths.h: ${srcdir}/paths.h.in Makefile ${top_builddir}/config.status
	rm -f $@.tmp
	sed < ${srcdir}/$@.in > $@.tmp \
	    -e 's:@-PKGSYSCONFDIR-@:${pkgsysconfdir}:' \
	    -e 's:@-XMLDIR-@:${xmldir}:'
	cmp -s $@ $@.tmp || mv $@.tmp $@
	rm -f $@.tmp

install-exec-hook:
	for la in $(lib_LTLIBRARIES) ; do rm -f $(DESTDIR)$(libdir)/$$la ; done

EXTRA_DIST = shibsp.vcproj paths.h.in resource.h shibsp.rc
BUILT_SOURCES = paths.h

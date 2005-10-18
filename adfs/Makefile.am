## $Id$

AUTOMAKE_OPTIONS = foreign

plugindir = $(libexecdir)
plugin_LTLIBRARIES = adfs.la

noinst_HEADERS = internal.h

adfs_la_LIBADD = \
	../shib/libshib.la \
	../shib-target/libshib-target.la

adfs_la_SOURCES = \
	adfs.cpp \
	listener.cpp \
	handlers.cpp \
	XML.cpp


adfs_la_LDFLAGS = -module -avoid-version

install-exec-hook:
	for la in $(plugin_LTLIBRARIES) ; do rm -f $(DESTDIR)$(plugindir)/$$la ; done

EXTRA_DIST = adfs.dsp resource.h adfs.rc

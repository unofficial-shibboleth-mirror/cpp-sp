## $Id$

AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libshib.la

libshibdir = $(includedir)/shib
libshib_HEADERS = shib.h shib-threads.h
noinst_HEADERS = internal.h

libshib_la_SOURCES = \
                    Constants.cpp \
                    Metadata.cpp \
                    ReloadableXMLFile.cpp \
                    ShibConfig.cpp \
                    ShibBrowserProfile.cpp \
                    ShibHTTPHook.cpp \
                    shib-threads.cpp


# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
libshib_la_LDFLAGS = -version-info 6:0:0

install-exec-hook:
	for la in $(lib_LTLIBRARIES) ; do rm -f $(DESTDIR)$(libdir)/$$la ; done

EXTRA_DIST = shib.dsp shib-threads-win32.cpp resource.h shib.rc


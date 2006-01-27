AUTOMAKE_OPTIONS = foreign

plugindir = $(libexecdir)
plugin_LTLIBRARIES = odbc_ccache.la

AM_CFLAGS = $(ODBC_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS)

shib_mysql_ccache_la_LIBADD = \
	../shib-target/libshib-target.la \
	../shib/libshib.la \
	$(ODBC_LIBS)

odbc_ccache_la_SOURCES = \
	odbc-ccache.cpp

odbc_ccache_la_LDFLAGS = -module -avoid-version

install-exec-hook:
	for la in $(plugin_LTLIBRARIES) ; do rm -f $(DESTDIR)$(plugindir)/$$la ; done

EXTRA_DIST = odbc_ccache.vcproj odbc_ccache.rc resource.h

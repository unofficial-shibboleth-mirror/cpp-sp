AUTOMAKE_OPTIONS = foreign

plugindir = $(libexecdir)
plugin_LTLIBRARIES = shib-mysql-ccache.la

AM_CFLAGS = $(MYSQL_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS)

shib_mysql_ccache_la_LIBADD = \
	../shib-target/libshib-target.la \
	../shib/libshib.la \
	$(MYSQL_LIBS)

shib_mysql_ccache_la_SOURCES = \
	shib-mysql-ccache.cpp

shib_mysql_ccache_la_LDFLAGS = -module -avoid-version

install-exec-hook:
	for la in $(plugin_LTLIBRARIES) ; do rm -f $(DESTDIR)$(plugindir)/$$la ; done

EXTRA_DIST = shib_mysql_ccache.dsp


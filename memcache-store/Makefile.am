AUTOMAKE_OPTIONS = foreign

plugindir = $(libdir)/@PACKAGE_NAME@
plugin_LTLIBRARIES = memcache-store.la

AM_CFLAGS = $(MEMCACHED_INCLUDE)
AM_CXXFLAGS = $(MEMCACHED_INCLUDE)

memcache_store_la_LDFLAGS = $(MEMCACHED_LDFLAGS) -module -avoid-version
memcache_store_la_LIBADD = $(XMLSEC_LIBS) $(MEMCACHED_LIBS)

memcache_store_la_SOURCES = \
	memcache-store.cpp

install-data-hook:
	for la in $(plugin_LTLIBRARIES) ; do rm -f $(DESTDIR)$(plugindir)/$$la ; done

EXTRA_DIST = memcache-store.vcxproj memcache-store.rc resource.h

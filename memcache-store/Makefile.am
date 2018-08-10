AUTOMAKE_OPTIONS = foreign

plugindir = $(libdir)/@PACKAGE_NAME@
plugin_LTLIBRARIES = memcache-store.la

memcache_store_la_LDFLAGS = $(MEMCACHED_LDFLAGS) -module -avoid-version
memcache_store_la_CXXFLAGS = \
	$(AM_CXXFLAGS) \
	$(MEMCACHED_INCLUDE) \
	$(BOOST_CPPFLAGS) \
	$(PTHREAD_CFLAGS) \
	$(opensaml_CFLAGS) \
	$(xerces_CFLAGS) \
	$(xmltooling_CFLAGS)
memcache_store_la_LIBADD = \
	$(MEMCACHED_LIBS) \
	$(PTHREAD_LIBS) \
	$(opensaml_LIBS) \
	$(xerces_LIBS) \
	$(xmltooling_LIBS)

memcache_store_la_SOURCES = \
	memcache-store.cpp

EXTRA_DIST = memcache-store.rc resource.h

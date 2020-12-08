AUTOMAKE_OPTIONS = foreign

plugindir = $(libdir)/@PACKAGE_NAME@
plugin_LTLIBRARIES = odbc-store.la

odbc_store_la_CXXFLAGS = \
	$(AM_CXXFLAGS) \
	$(ODBC_CFLAGS) \
	$(BOOST_CPPFLAGS) \
	$(PTHREAD_CFLAGS) \
	$(log4cpp_CFLAGS) \
	$(log4shib_CFLAGS) \
	$(opensaml_CFLAGS) \
	$(xerces_CFLAGS) \
	$(xmltooling_CFLAGS)
odbc_store_la_LIBADD = \
	$(ODBC_LIBS) \
	$(PTHREAD_LIBS) \
	$(log4cpp_LIBS) \
	$(log4shib_LIBS) \
	$(opensaml_LIBS) \
	$(xerces_LIBS) \
	$(xmltooling_LIBS)

odbc_store_la_SOURCES = \
	odbc-store.cpp

odbc_store_la_LDFLAGS = -module -avoid-version

EXTRA_DIST = odbc-store.rc resource.h

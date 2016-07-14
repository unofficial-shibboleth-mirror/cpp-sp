AUTOMAKE_OPTIONS = foreign

plugindir = $(libdir)/@PACKAGE_NAME@
plugin_LTLIBRARIES = odbc-store.la

AM_CFLAGS = $(ODBC_CFLAGS)
AM_CXXFLAGS = $(ODBC_CFLAGS)

odbc_store_la_CXXFLAGS = \
	$(BOOST_CPPFLAGS) \
	$(PTHREAD_CFLAGS) \
	$(xmltooling_CFLAGS)
odbc_store_la_LIBADD = $(XMLSEC_LIBS) $(ODBC_LIBS) \
	$(PTHREAD_LIBS) \
	$(xmltooling_LIBS)

odbc_store_la_SOURCES = \
	odbc-store.cpp

odbc_store_la_LDFLAGS = -module -avoid-version

EXTRA_DIST = odbc-store.rc resource.h

AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = mdquery resolvertest

resolvertest_SOURCES = resolvertest.cpp

resolvertest_CXXFLAGS = \
	$(log4shib_CFLAGS) $(log4cpp_CFLAGS) \
	$(xmltooling_CFLAGS)
resolvertest_LDADD = \
	$(top_builddir)/shibsp/libshibsp.la \
	$(log4shib_LIBS) $(log4cpp_LIBS) \
	$(xmltooling_LIBS) \
	$(XMLSEC_LIBS)

mdquery_SOURCES = mdquery.cpp

EXTRA_DIST = \
	resource.h \
	mdquery.rc \
	resolvertest.rc

mdquery_CXXFLAGS = \
	$(log4shib_CFLAGS) $(log4cpp_CFLAGS) \
	$(xmltooling_CFLAGS)
mdquery_LDADD = \
	$(top_builddir)/shibsp/libshibsp.la \
	$(log4shib_LIBS) $(log4cpp_LIBS) \
	$(xmltooling_LIBS) \
	$(XMLSEC_LIBS)

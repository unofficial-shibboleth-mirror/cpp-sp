AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = mdquery resolvertest

resolvertest_SOURCES = resolvertest.cpp

resolvertest_LDADD = $(XMLSEC_LIBS) \
	$(top_builddir)/shibsp/libshibsp.la

mdquery_SOURCES = mdquery.cpp

mdquery_LDADD = $(XMLSEC_LIBS) \
	$(top_builddir)/shibsp/libshibsp.la

EXTRA_DIST = mdquery.vcxproj \
	resolvertest.vcxproj \
	resource.h \
	mdquery.rc \
	resolvertest.rc
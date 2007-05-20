## $Id$

AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = samlquery siterefresh

samlquery_SOURCES = samlquery.cpp

samlquery_LDADD = \
	$(top_builddir)/shibsp/libshibsp.la

samlquery_LDFLAGS = $(XMLSEC_LIBS)

siterefresh_SOURCES = siterefresh.cpp

siterefresh_LDFLAGS = $(XMLSEC_LIBS)

EXTRA_DIST = samlquery.vcproj siterefresh.vcproj

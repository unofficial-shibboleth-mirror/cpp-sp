## $Id$

AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = samlquery mdquery
sbin_PROGRAMS = siterefresh

samlquery_SOURCES = samlquery.cpp

samlquery_LDADD = \
	$(top_builddir)/shibsp/libshibsp.la

samlquery_LDFLAGS = $(XMLSEC_LIBS)

mdquery_SOURCES = mdquery.cpp

mdquery_LDADD = \
	$(top_builddir)/shibsp/libshibsp.la

mdquery_LDFLAGS = $(XMLSEC_LIBS)

siterefresh_SOURCES = siterefresh.cpp

siterefresh_LDFLAGS = $(XMLSEC_LIBS)

EXTRA_DIST = mdquery.vcproj samlquery.vcproj siterefresh.vcproj

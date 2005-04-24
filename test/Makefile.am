## $Id$

AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = shibtest posttest

shibtest_SOURCES = shibtest.cpp

posttest_SOURCES = posttest.cpp

shibtest_LDADD = $(top_builddir)/shib/libshib.la \
	$(top_builddir)/shib-target/libshib-target.la

posttest_LDADD = $(top_builddir)/shib/libshib.la \
	$(top_builddir)/shib-target/libshib-target.la

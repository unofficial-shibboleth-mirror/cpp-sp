## $Id$

AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = shibtest posttest
noinst_PROGRAMS = inittest

shibtest_SOURCES = shibtest.cpp

posttest_SOURCES = posttest.cpp

inittest_SOURCES = inittest.cpp

shibtest_LDADD = $(top_builddir)/shib/libshib.la \
	$(top_builddir)/shib-target/libshib-target.la

posttest_LDADD = $(top_builddir)/shib/libshib.la \
	$(top_builddir)/shib-target/libshib-target.la

inittest_LDADD = $(top_builddir)/shib/libshib.la \
	$(top_builddir)/shib-target/libshib-target.la

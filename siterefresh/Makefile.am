## $Id$

AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = siterefresh

AM_CXXFLAGS = -DDEFAULT_SCHEMA_DIR=\"$(sysconfdir)/@PACKAGE@/\"

siterefresh_SOURCES = siterefresh.cpp

siterefresh_LDADD = \
  $(top_builddir)/shib/libshib.la

EXTRA_DIST = siterefresh.dsp

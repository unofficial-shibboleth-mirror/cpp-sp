## $Id$

AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = mod_shire.la

mod_shire_la_SOURCES = mod_shire.cpp

AM_CXXFLAGS = $(APXS_CFLAGS) -I$(APXS_INCLUDE)

mod_shire_la_LIBADD = $(top_builddir)/shib/libshib.la $(top_builddir)/shib-target/libshib-target.la

mod_shire_la_LDFLAGS = -module -avoid-version -lapreq

install-exec-local:
	$(APXS) -i -A -n shire .libs/mod_shire.so

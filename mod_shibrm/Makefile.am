## $Id$

AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = mod_shibrm.la

mod_shibrm_la_SOURCES = mod_shibrm.cpp

mod_shibrm_la_CXXFLAGS = $(APXS_CFLAGS) -I$(APXS_INCLUDE)

mod_shibrm_la_LIBADD = $(top_builddir)/shib/libshib.la $(top_builddir)/shib-target/libshib-target.la

mod_shibrm_la_LDFLAGS = -module -avoid-version -lapreq

install-exec-local:
	$(APXS) -i -A -n shibrm .libs/mod_shibrm.so

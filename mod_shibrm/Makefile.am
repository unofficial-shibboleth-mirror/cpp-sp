## $Id$

AUTOMAKE_OPTIONS = foreign

shibrmdir = $(libexecdir)
shibrm_LTLIBRARIES = mod_shibrm.la

mod_shibrm_la_SOURCES = mod_shibrm.cpp

AM_CXXFLAGS = $(APXS_CFLAGS) -I$(APXS_INCLUDE)

mod_shibrm_la_LIBADD = $(top_builddir)/shib/libshib.la $(top_builddir)/shib-target/libshib-target.la

mod_shibrm_la_LDFLAGS = -module -avoid-version -lapreq

if DO_APXS_INSTALL
install-exec-local:
	$(APXS) -i -A -n shibrm .libs/mod_shibrm.so
endif 

## $Id$

AUTOMAKE_OPTIONS = foreign

if USE_OUR_ONCRPC
RPC_CFLAGS = -I${top_srcdir}/oncrpc
endif

shiredir = $(libexecdir)
shire_LTLIBRARIES = mod_shire.la

mod_shire_la_SOURCES = mod_shire.cpp

AM_CXXFLAGS = $(APXS_CFLAGS) -I$(APXS_INCLUDE) $(RPC_CFLAGS)

mod_shire_la_LIBADD = $(top_builddir)/shib/libshib.la $(top_builddir)/shib-target/libshib-target.la

mod_shire_la_LDFLAGS = -module -avoid-version -lapreq

if DO_APXS_INSTALL
install-exec-local:
	$(APXS) -i -A -n shire .libs/mod_shire.so
endif

## $Id$

AUTOMAKE_OPTIONS = foreign

if USE_OUR_ONCRPC
RPC_CFLAGS = -I${top_srcdir}/oncrpc
endif

modshibdir = $(libexecdir)
modshib_LTLIBRARIES = mod_shib.la

mod_shib_la_SOURCES = mod_shib.cpp

AM_CXXFLAGS = $(APXS2_CFLAGS) -I$(APXS2_INCLUDE) $(RPC_CFLAGS)

mod_shib_la_LIBADD = $(top_builddir)/shib/libshib.la $(top_builddir)/shib-target/libshib-target.la

mod_shib_la_LDFLAGS = -module -avoid-version -lapreq

if DO_APXS2_INSTALL
install-exec-local:
	$(APXS2) -i -A -n shib .libs/mod_shib.so
endif 

EXTRA_DIST = mod_shib.dsp

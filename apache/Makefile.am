## $Id$

AUTOMAKE_OPTIONS = foreign

if USE_OUR_ONCRPC
RPC_CFLAGS = -I${top_srcdir}/oncrpc
endif

if BUILD_AP13
modshib13dir = $(libexecdir)
modshib13_LTLIBRARIES = mod_shib_13.la
mod_shib_13_la_SOURCES = mod_shib_13.cpp
mod_shib_13_la_CXXFLAGS = $(APXS_CFLAGS) -I$(APXS_INCLUDE) $(RPC_CFLAGS)
mod_shib_13_la_LDFLAGS = -module -avoid-version
mod_shib_13_la_LIBADD = \
  $(top_builddir)/shib/libshib.la \
  $(top_builddir)/shib-target/libshib-target.la

if DO_APXS_INSTALL
install-exec-local::
	$(APXS) -i -A -n shib_13 .libs/mod_shib_13.so
endif
endif

if BUILD_AP20
modshib20dir = $(libexecdir)
modshib20_LTLIBRARIES = mod_shib_20.la
mod_shib_20_la_SOURCES = mod_shib_20.cpp
mod_shib_20_la_CXXFLAGS = $(APXS2_CFLAGS) -I$(APXS2_INCLUDE) $(RPC_CFLAGS)
mod_shib_20_la_LDFLAGS = -module -avoid-version
mod_shib_20_la_LIBADD = \
  $(top_builddir)/shib/libshib.la \
  $(top_builddir)/shib-target/libshib-target.la

if DO_APXS2_INSTALL
install-exec-local::
	$(APXS2) -i -A -n shib_20 .libs/mod_shib_20.so
endif 
endif

EXTRA_DIST = mod_apache.cpp

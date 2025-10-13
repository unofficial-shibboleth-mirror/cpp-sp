AUTOMAKE_OPTIONS = foreign

if BUILD_AP24
modshib4dir = $(libdir)/@PACKAGE_NAME@
modshib4_LTLIBRARIES = mod_shib4.la
mod_shib4_la_SOURCES = mod_shib4.cpp
mod_shib4_la_LDFLAGS = \
  -module -avoid-version \
  $(APXS24_LDFLAGS)
mod_shib4_la_CXXFLAGS = \
  $(AM_CXXFLAGS) \
  $(APXS24_CFLAGS) $(APXS24_INCLUDE) \
  $(BOOST_CPPFLAGS) \
  $(PTHREAD_CFLAGS)
mod_shib4_la_LIBADD = \
  $(APXS24_LIBS) \
  $(top_builddir)/shibsp/libshibsp.la \
  $(PTHREAD_LIBS)
endif

EXTRA_DIST = mod_shib4.cpp mod_shib4.rc

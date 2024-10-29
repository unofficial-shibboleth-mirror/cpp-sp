AUTOMAKE_OPTIONS = foreign

if BUILD_AP24
modshib24dir = $(libdir)/@PACKAGE_NAME@
modshib24_LTLIBRARIES = mod_shib_24.la
mod_shib_24_la_SOURCES = mod_shib_24.cpp
mod_shib_24_la_LDFLAGS = \
  -module -avoid-version \
  $(APXS24_LDFLAGS)
mod_shib_24_la_CXXFLAGS = \
  $(AM_CXXFLAGS) \
  $(APXS24_CFLAGS) $(APXS24_INCLUDE) \
  $(BOOST_CPPFLAGS) \
  $(PTHREAD_CFLAGS) \
  $(gss_CFLAGS) $(gnu_gss_CFLAGS) \
  $(xerces_CFLAGS) \
  $(xmltooling_lite_CFLAGS)
mod_shib_24_la_LIBADD = \
  $(APXS24_LIBS) \
  $(top_builddir)/shibsp/libshibsp-lite.la \
  $(PTHREAD_LIBS) \
  $(gss_LIBS) $(gnu_gss_LIBS) \
  $(xerces_LIBS) \
  $(xmltooling_lite_LIBS)
endif

EXTRA_DIST = mod_shib_24.cpp resource.h mod_shib_24.rc

AUTOMAKE_OPTIONS = foreign

if BUILD_NSAPI
nsapi_shibdir = $(libdir)/@PACKAGE_NAME@
nsapi_shib_LTLIBRARIES = nsapi_shib.la
nsapi_shib_la_SOURCES = nsapi_shib.cpp
nsapi_shib_la_CXXFLAGS = $(NSAPI_INCLUDE) \
  $(AM_CXXFLAGS) \
  $(BOOST_CPPFLAGS) \
  $(PTHREAD_CFLAGS) \
  $(log4shib_CFLAGS) $(log4cpp_CFLAGS) \
  $(xerces_CFLAGS) \
  $(xmltooling_lite_CFLAGS)
nsapi_shib_la_LDFLAGS = -module -avoid-version
nsapi_shib_la_LIBADD = \
  $(top_builddir)/shibsp/libshibsp-lite.la \
  $(PTHREAD_LIBS) \
  $(log4shib_LIBS) $(log4cpp_LIBS) \
  $(xerces_LIBS) \
  $(xmltooling_lite_LIBS)
endif

EXTRA_DIST = resource.h nsapi_shib.rc nsapi_shib.cpp

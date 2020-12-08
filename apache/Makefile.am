AUTOMAKE_OPTIONS = foreign

if BUILD_AP13
modshib13dir = $(libdir)/@PACKAGE_NAME@
modshib13_LTLIBRARIES = mod_shib_13.la
mod_shib_13_la_SOURCES = mod_shib_13.cpp
mod_shib_13_la_LDFLAGS = \
  -module -avoid-version \
  $(APXS_LDFLAGS)
mod_shib_13_la_CXXFLAGS = \
  $(AM_CXXFLAGS) \
  $(APXS_CFLAGS) $(APXS_INCLUDE) \
  $(BOOST_CPPFLAGS) \
  $(PTHREAD_CFLAGS) \
  $(xerces_CFLAGS) \
  $(xmltooling_lite_CFLAGS)
mod_shib_13_la_LIBADD = \
  $(top_builddir)/shibsp/libshibsp-lite.la \
  $(PTHREAD_LIBS) \
  $(xerces_LIBS) \
  $(xmltooling_lite_LIBS)
endif

if BUILD_AP20
modshib20dir = $(libdir)/@PACKAGE_NAME@
modshib20_LTLIBRARIES = mod_shib_20.la
mod_shib_20_la_SOURCES = mod_shib_20.cpp
mod_shib_20_la_LDFLAGS = \
  -module -avoid-version \
  $(APXS2_LDFLAGS)
mod_shib_20_la_CXXFLAGS = \
  $(AM_CXXFLAGS) \
  $(APXS2_CFLAGS) $(APXS2_INCLUDE) \
  $(BOOST_CPPFLAGS) \
  $(PTHREAD_CFLAGS) \
  $(gss_CFLAGS) $(gnu_gss_CFLAGS) \
  $(xerces_CFLAGS) \
  $(xmltooling_lite_CFLAGS)
mod_shib_20_la_LIBADD = \
  $(APXS2_LIBS) \
  $(top_builddir)/shibsp/libshibsp-lite.la \
  $(PTHREAD_LIBS) \
  $(gss_LIBS) $(gnu_gss_LIBS) \
  $(xerces_LIBS) \
  $(xmltooling_lite_LIBS)
endif

if BUILD_AP22
modshib22dir = $(libdir)/@PACKAGE_NAME@
modshib22_LTLIBRARIES = mod_shib_22.la
mod_shib_22_la_SOURCES = mod_shib_22.cpp
mod_shib_22_la_LDFLAGS = \
  -module -avoid-version \
  $(APXS22_LDFLAGS)
mod_shib_22_la_CXXFLAGS = \
  $(AM_CXXFLAGS) \
  $(APXS22_CFLAGS) $(APXS22_INCLUDE) \
  $(BOOST_CPPFLAGS) \
  $(PTHREAD_CFLAGS) \
  $(gss_CFLAGS) $(gnu_gss_CFLAGS) \
  $(xerces_CFLAGS) \
  $(xmltooling_lite_CFLAGS)
mod_shib_22_la_LIBADD = \
  $(APXS22_LIBS) \
  $(top_builddir)/shibsp/libshibsp-lite.la \
  $(PTHREAD_LIBS) \
  $(gss_LIBS) $(gnu_gss_LIBS) \
  $(xerces_LIBS) \
  $(xmltooling_lite_LIBS)
endif

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

EXTRA_DIST = mod_shib.cpp \
	mod_shib_13.cpp mod_shib_20.cpp mod_shib_22.cpp mod_shib_24.cpp \
	resource.h mod_shib_13.rc mod_shib_20.rc mod_shib_22.rc mod_shib_24.rc

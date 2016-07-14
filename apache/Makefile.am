AUTOMAKE_OPTIONS = foreign

if BUILD_AP13
modshib13dir = $(libdir)/@PACKAGE_NAME@
modshib13_LTLIBRARIES = mod_shib_13.la
mod_shib_13_la_SOURCES = mod_shib_13.cpp
mod_shib_13_la_LDFLAGS = -module -avoid-version
mod_shib_13_la_CXXFLAGS = \
  $(APXS_CFLAGS) -I$(APXS_INCLUDE) \
  $(BOOST_CPPFLAGS) \
  $(PTHREAD_CFLAGS) \
  $(xmltooling_lite_CFLAGS)
mod_shib_13_la_LIBADD = \
  $(top_builddir)/shibsp/libshibsp-lite.la \
  $(PTHREAD_LIBS) \
  $(xmltooling_lite_LIBS)
endif

if BUILD_AP20
modshib20dir = $(libdir)/@PACKAGE_NAME@
modshib20_LTLIBRARIES = mod_shib_20.la
mod_shib_20_la_SOURCES = mod_shib_20.cpp
mod_shib_20_la_LDFLAGS = -module -avoid-version
mod_shib_20_la_CXXFLAGS = \
  $(APXS2_CFLAGS) -I$(APXS2_INCLUDE) \
  $(BOOST_CPPFLAGS) \
  $(PTHREAD_CFLAGS) \
  $(xmltooling_lite_CFLAGS)
mod_shib_20_la_LIBADD = \
  $(top_builddir)/shibsp/libshibsp-lite.la \
  $(PTHREAD_LIBS) \
  $(xmltooling_lite_LIBS)
endif

if BUILD_AP22
modshib22dir = $(libdir)/@PACKAGE_NAME@
modshib22_LTLIBRARIES = mod_shib_22.la
mod_shib_22_la_SOURCES = mod_shib_22.cpp
mod_shib_22_la_LDFLAGS = -module -avoid-version
mod_shib_22_la_CXXFLAGS = \
  $(APXS22_CFLAGS) -I$(APXS22_INCLUDE) \
  $(BOOST_CPPFLAGS) \
  $(PTHREAD_CFLAGS) \
  $(xmltooling_lite_CFLAGS)
mod_shib_22_la_LIBADD = \
  $(top_builddir)/shibsp/libshibsp-lite.la \
  $(PTHREAD_LIBS) \
  $(xmltooling_lite_LIBS)
endif

if BUILD_AP24
modshib24dir = $(libdir)/@PACKAGE_NAME@
modshib24_LTLIBRARIES = mod_shib_24.la
mod_shib_24_la_SOURCES = mod_shib_24.cpp
mod_shib_24_la_LDFLAGS = -module -avoid-version
mod_shib_24_la_CXXFLAGS = \
  $(APXS24_CFLAGS) -I$(APXS24_INCLUDE) \
  $(BOOST_CPPFLAGS) \
  $(PTHREAD_CFLAGS) \
  $(xmltooling_lite_CFLAGS)
mod_shib_24_la_LIBADD = \
  $(top_builddir)/shibsp/libshibsp-lite.la \
  $(PTHREAD_LIBS) \
  $(xmltooling_lite_LIBS)
endif

EXTRA_DIST = mod_shib.cpp \
	mod_shib_13.cpp mod_shib_20.cpp mod_shib_22.cpp mod_shib_24.cpp \
	resource.h mod_shib_13.rc mod_shib_20.rc mod_shib_22.rc mod_shib_24.rc

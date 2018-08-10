AUTOMAKE_OPTIONS = foreign

if BUILD_FASTCGI

fastcgidir = $(libdir)/@PACKAGE_NAME@

fastcgi_PROGRAMS = shibauthorizer shibresponder

shibauthorizer_SOURCES = shibauthorizer.cpp
shibauthorizer_CXXFLAGS = $(FASTCGI_INCLUDE) \
  $(AM_CXXFLAGS) \
  $(BOOST_CPPFLAGS) \
  $(PTHREAD_CFLAGS) \
  $(xerces_CFLAGS) \
  $(xmltooling_lite_CFLAGS)
shibauthorizer_LDFLAGS = $(FASTCGI_LDFLAGS)
shibauthorizer_LDADD = $(FASTCGI_LIBS) \
  $(top_builddir)/shibsp/libshibsp-lite.la \
  $(PTHREAD_LIBS) \
  $(xerces_LIBS) \
  $(xmltooling_lite_LIBS)

shibresponder_SOURCES = shibresponder.cpp
shibresponder_CXXFLAGS = $(FASTCGI_INCLUDE) \
  $(AM_CXXFLAGS) \
  $(BOOST_CPPFLAGS) \
  $(PTHREAD_CFLAGS) \
  $(xerces_CFLAGS) \
  $(xmltooling_lite_CFLAGS)
shibresponder_LDFLAGS = $(FASTCGI_LDFLAGS)
shibresponder_LDADD = $(FASTCGI_LIBS) \
  $(top_builddir)/shibsp/libshibsp-lite.la \
  $(PTHREAD_LIBS) \
  $(xerces_LIBS) \
  $(xmltooling_lite_LIBS)

endif

EXTRA_DIST = \
    shibauthorizer.cpp \
    shibauthorizer.rc \
    shibresponder.cpp \
    shibresponder.rc \
    resource.h

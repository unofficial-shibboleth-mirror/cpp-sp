AUTOMAKE_OPTIONS = foreign

if BUILD_FASTCGI

fastcgidir = $(libdir)/@PACKAGE_NAME@

fastcgi_PROGRAMS = shibauthorizer shibresponder

shibauthorizer_SOURCES = shibauthorizer.cpp
shibauthorizer_CXXFLAGS = $(FASTCGI_INCLUDE)
shibauthorizer_LDFLAGS = $(FASTCGI_LDFLAGS)
shibauthorizer_LDADD = $(FASTCGI_LIBS) \
  $(top_builddir)/shibsp/libshibsp-lite.la \
  $(LITE_LIBS)

shibresponder_SOURCES = shibresponder.cpp
shibresponder_CXXFLAGS = $(FASTCGI_INCLUDE)
shibresponder_LDFLAGS = $(FASTCGI_LDFLAGS)
shibresponder_LDADD = $(FASTCGI_LIBS) \
  $(top_builddir)/shibsp/libshibsp-lite.la \
  $(LITE_LIBS)

endif

EXTRA_DIST = \
    shibauthorizer.cpp \
    shibauthorizer.vcxproj \
    shibauthorizer.rc \
    shibresponder.cpp \
    shibresponder.vcxproj \
    shibresponder.rc \
    resource.h

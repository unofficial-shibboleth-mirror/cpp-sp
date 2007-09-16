AUTOMAKE_OPTIONS = foreign

if BUILD_FASTCGI

libexec_PROGRAMS = shibauthorizer shibresponder

shibauthorizer_SOURCES = shibauthorizer.cpp
shibauthorizer_CXXFLAGS = -I$(FASTCGI_INCLUDE)
shibauthorizer_LDFLAGS = $(FASTCGI_LDFLAGS) $(FASTCGI_LIBS)
shibauthorizer_LDADD = \
  $(top_builddir)/shib/libshib.la \
  $(top_builddir)/shib-target/libshib-target.la

shibresponder_SOURCES = shibresponder.cpp
shibresponder_CXXFLAGS = -I$(FASTCGI_INCLUDE)
shibresponder_LDFLAGS = $(FASTCGI_LDFLAGS) $(FASTCGI_LIBS)
shibresponder_LDADD = \
  $(top_builddir)/shib/libshib.la \
  $(top_builddir)/shib-target/libshib-target.la

endif

EXTRA_DIST = shibauthorizer.cpp shibresponder.cpp shibauthorizer.dsp shibresponder.dsp

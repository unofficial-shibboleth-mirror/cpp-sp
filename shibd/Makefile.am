AUTOMAKE_OPTIONS = foreign

sbin_PROGRAMS = shibd

shibd_SOURCES = shibd.cpp

shibd_CXXFLAGS = \
  $(PTHREAD_CFLAGS) \
  $(SYSTEMD_CFLAGS) \
  $(opensaml_CFLAGS) \
  $(xerces_CFLAGS) \
  $(xmltooling_CFLAGS)
shibd_LDADD = \
  $(top_builddir)/shibsp/libshibsp.la \
  $(PTHREAD_LIBS) \
  $(SYSTEMD_LIBS) \
  $(opensaml_LIBS) \
  $(xerces_LIBS) \
  $(xmltooling_LIBS)

EXTRA_DIST = shibd_win32.cpp resource.h shibd.rc

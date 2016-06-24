AUTOMAKE_OPTIONS = foreign

sbin_PROGRAMS = shibd

shibd_SOURCES = shibd.cpp

shibd_CXXFLAGS = $(SYSTEMD_CFLAGS)

shibd_LDADD = $(XMLSEC_LIBS) \
  $(top_builddir)/shibsp/libshibsp.la $(SYSTEMD_LIBS)

EXTRA_DIST = shibd_win32.cpp resource.h shibd.rc

AUTOMAKE_OPTIONS = foreign

sbin_PROGRAMS = shibd

shibd_SOURCES = shibd.cpp

shibd_LDADD = $(XMLSEC_LIBS) \
  $(top_builddir)/shibsp/libshibsp.la

EXTRA_DIST = shibd.vcxproj shibd_win32.cpp resource.h shibd.rc

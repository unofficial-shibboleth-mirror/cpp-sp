## $Id$

AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = test-client
sbin_PROGRAMS = shibd

if USE_OUR_ONCRPC
AM_CFLAGS = -I${top_srcdir}/oncrpc
AM_CXXFLAGS = -I${top_srcdir}/oncrpc
ONCRPC_LIBS = ${top_builddir}/oncrpc/liboncrpc.la
endif

test_client_SOURCES = test-client.cpp

shibd_SOURCES = shar.cpp

test_client_LDADD = \
  $(top_builddir)/shib-target/libshib-target.la \
  $(top_builddir)/shib/libshib.la

shibd_LDADD = \
  $(top_builddir)/shib-target/libshib-target.la \
  $(top_builddir)/shib/libshib.la \
  $(ONCRPC_LIBS)

EXTRA_DIST = shar.vcproj shar_win32.cpp testclient.vcproj resource.h shar.rc

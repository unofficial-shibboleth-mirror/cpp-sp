## $Id$

AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = shar test-client

if USE_OUR_ONCRPC
AM_CFLAGS = -I${top_srcdir}/oncrpc
ONCRPC_LIBS = ${top_builddir}/oncrpc/liboncrpc.la
endif

test_client_SOURCES = test-client.c

shar_SOURCES = shar.c

test_client_LDADD = \
  $(top_builddir)/shib-target/libshib-target.la \
  $(top_builddir)/shib/libshib.la

shar_LDADD = \
  $(top_builddir)/shib-target/libshib-target.la \
  $(top_builddir)/shib/libshib.la \
  $(ONCRPC_LIBS)

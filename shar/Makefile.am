## $Id$

AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = shar test-client

test_client_SOURCES = test-client.c

shar_SOURCES = shar.c

test_client_LDADD = $(top_builddir)/shib-target/libshib-target.la \
        $(top_builddir)/shib/libshib.la

if USE_OUR_ONCRPC
shar_LDADD = ${top_builddir}/oncrpc/liboncrpc.la \
	$(top_builddir)/shib-target/libshib-target.la \
        $(top_builddir)/shib/libshib.la
AM_CFLAGS = -I${top_srcdir}/oncrpc
else
shar_LDADD = $(top_builddir)/shib-target/libshib-target.la \
	$(top_builddir)/shib/libshib.la
endif


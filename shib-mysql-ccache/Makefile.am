AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libshib-mysql-ccache.la

AM_CFLAGS = $(MYSQL_CFLAGS)
AM_CXXFLAGS = $(AM_CFLAGS)

libshib_mysql_ccache_la_LIBADD = \
	../shib-target/libshib-target.la \
	../shib/libshib.la \
	$(MYSQL_LIBS)

libshib_mysql_ccache_la_SOURCES = \
	shib-mysql-ccache.cpp

# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
libshib_mysql_ccache_la_LDFLAGS = -version-info 1:0:0

EXTRA_DIST = shib_mysql_ccache.dsp

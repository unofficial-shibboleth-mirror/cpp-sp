AUTOMAKE_OPTIONS = foreign

if USE_OUR_ONCRPC
RPC_CFLAGS = -I${top_srcdir}/oncrpc
endif

if BUILD_NSAPI
nsapi_shibdir = $(libexecdir)
nsapi_shib_LTLIBRARIES = nsapi_shib.la
nsapi_shib_la_SOURCES = nsapi_shib.cpp
nsapi_shib_la_CXXFLAGS = $(NSAPI_INCLUDE) $(RPC_CFLAGS)
nsapi_shib_la_LDFLAGS = -module -avoid-version
nsapi_shib_la_LIBADD = \
  $(top_builddir)/shib/libshib.la \
  $(top_builddir)/shib-target/libshib-target.la

install-exec-hook:
	for la in $(nsapi_shib_LTLIBRARIES) ; do rm -f $(DESTDIR)$(nsapi_shibdir)/$$la ; done

endif

EXTRA_DIST = nsapi_shib.dsp resource.h nsapi_shib.rc nsapi_shib.cpp


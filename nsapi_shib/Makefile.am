AUTOMAKE_OPTIONS = foreign

if USE_OUR_ONCRPC
RPC_CFLAGS = -I${top_srcdir}/oncrpc
endif

if BUILD_NSAPI
nsapishibdir = $(libexecdir)
nsapishib_LTLIBRARIES = nsapi_shib.la
nsapishib_la_SOURCES = nsapi_shib.cpp
nsapishib_la_CXXFLAGS = $(NSAPI_CFLAGS) -I$(NSAPI_INCLUDE) $(RPC_CFLAGS)
nsapishib_la_LDFLAGS = -module -avoid-version
nsapishib_la_LIBADD = \
  $(top_builddir)/shib/libshib.la \
  $(top_builddir)/shib-target/libshib-target.la

install-exec-hook:
	for la in $(nsapishib_LTLIBRARIES) ; do rm -f $(DESTDIR)$(nsapishibdir)/$$la ; done

endif

EXTRA_DIST = nsapi_shib.dsp resource.h nsapi_shib.rc nsapi_shib.cpp

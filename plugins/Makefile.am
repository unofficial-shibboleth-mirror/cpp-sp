AUTOMAKE_OPTIONS = foreign

plugindir = $(libdir)/@PACKAGE_NAME@
plugin_LTLIBRARIES = plugins.la plugins-lite.la

noinst_HEADERS = \
	internal.h

common_sources = \
	plugins.cpp \
	AttributeResolverHandler.cpp \
	TimeAccessControl.cpp

plugins_la_SOURCES = \
	${common_sources} \
	CaseFoldingAttributeResolver.cpp \
	TemplateAttributeResolver.cpp \
	TransformAttributeResolver.cpp

plugins_lite_la_SOURCES = \
	${common_sources}

plugins_la_CXXFLAGS = \
	$(AM_CXXFLAGS) \
	$(BOOST_CPPFLAGS) \
	$(PTHREAD_CFLAGS) \
	$(log4cpp_CFLAGS) \
	$(log4shib_CFLAGS) \
	$(opensaml_CFLAGS) \
	$(xerces_CFLAGS) \
	$(xmltooling_CFLAGS)
plugins_la_LIBADD = \
	$(top_builddir)/shibsp/libshibsp.la \
	$(PTHREAD_LIBS) \
	$(log4cpp_LIBS) \
	$(log4shib_LIBS) \
	$(opensaml_LIBS) \
	$(xerces_LIBS) \
	$(xmltooling_LIBS)

if GSSAPI_NAMINGEXTS
plugins_la_SOURCES  += GSSAPIAttributeExtractor.cpp
plugins_la_CXXFLAGS += $(gss_CFLAGS) $(gnu_gss_CFLAGS)
plugins_la_LIBADD   += $(gss_LIBS)   $(gnu_gss_LIBS)
endif

plugins_lite_la_LIBADD = \
	$(top_builddir)/shibsp/libshibsp-lite.la \
	$(PTHREAD_LIBS) \
	$(log4cpp_LIBS) \
	$(log4shib_LIBS) \
	$(xerces_LIBS) \
	$(xmltooling_lite_LIBS)

plugins_la_LDFLAGS = -module -avoid-version
plugins_lite_la_LDFLAGS = -module -avoid-version
plugins_lite_la_CXXFLAGS = -DSHIBSP_LITE \
	$(AM_CXXFLAGS) \
	$(BOOST_CPPFLAGS) \
	$(PTHREAD_CFLAGS) \
	$(log4cpp_CFLAGS) \
	$(log4shib_CFLAGS) \
	$(xerces_CFLAGS) \
	$(xmltooling_lite_CFLAGS)

EXTRA_DIST = resource.h plugins.rc

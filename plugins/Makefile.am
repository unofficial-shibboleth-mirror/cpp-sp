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
	GSSAPIAttributeExtractor.cpp \
	TemplateAttributeResolver.cpp \
	TransformAttributeResolver.cpp

plugins_lite_la_SOURCES = \
	${common_sources}

plugins_la_CXXFLAGS = \
	$(PTHREAD_CFLAGS) \
	$(xmltooling_CFLAGS)
plugins_la_LIBADD = $(XMLSEC_LIBS) \
	$(top_builddir)/shibsp/libshibsp.la \
	$(PTHREAD_LIBS) \
	$(xmltooling_LIBS)

plugins_lite_la_LIBADD = \
	$(top_builddir)/shibsp/libshibsp-lite.la \
	$(PTHREAD_LIBS) \
	$(xmltooling_lite_LIBS)

plugins_la_LDFLAGS = -module -avoid-version
plugins_lite_la_LDFLAGS = -module -avoid-version
plugins_lite_la_CXXFLAGS = -DSHIBSP_LITE \
	$(PTHREAD_CFLAGS) \
	$(xmltooling_lite_CFLAGS)

EXTRA_DIST = resource.h plugins.rc

AUTOMAKE_OPTIONS = foreign

plugindir = $(libdir)/@PACKAGE@
plugin_LTLIBRARIES = plugins.la

noinst_HEADERS = \
	internal.h

common_sources = \
	plugins.cpp

plugins_la_SOURCES = \
	${common_sources} \
	GSSAPIAttributeExtractor.cpp \
    TemplateAttributeResolver.cpp \
    TransformAttributeResolver.cpp

#plugins_lite_la_SOURCES = \
#	${common_sources}

plugins_la_LIBADD = $(XMLSEC_LIBS) \
	$(top_builddir)/shibsp/libshibsp.la

#plugins_lite_la_LIBADD = $(LITE_LIBS) \
#	$(top_builddir)/shibsp/libshibsp-lite.la

plugins_la_LDFLAGS = -module -avoid-version
#plugins_lite_la_LDFLAGS = -module -avoid-version
#plugins_lite_la_CPPFLAGS = -DSHIBSP_LITE

install-exec-hook:
	for la in $(plugin_LTLIBRARIES) ; do rm -f $(DESTDIR)$(plugindir)/$$la ; done

EXTRA_DIST = plugins.vcxproj resource.h plugins.rc

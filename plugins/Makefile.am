AUTOMAKE_OPTIONS = foreign

plugindir = $(libdir)/@PACKAGE_NAME@
plugin_LTLIBRARIES = plugins.la plugins-lite.la

noinst_HEADERS = \
	internal.h

common_sources = \
	plugins.cpp \
	TimeAccessControl.cpp

plugins_la_SOURCES = \
	${common_sources} \
	CaseFoldingAttributeResolver.cpp \
	GSSAPIAttributeExtractor.cpp \
	TemplateAttributeResolver.cpp \
	TransformAttributeResolver.cpp

plugins_lite_la_SOURCES = \
	${common_sources}

plugins_la_LIBADD = $(XMLSEC_LIBS) \
	$(top_builddir)/shibsp/libshibsp.la

plugins_lite_la_LIBADD = $(LITE_LIBS) \
	$(top_builddir)/shibsp/libshibsp-lite.la

plugins_la_LDFLAGS = -module -avoid-version
plugins_lite_la_LDFLAGS = -module -avoid-version
plugins_lite_la_CPPFLAGS = -DSHIBSP_LITE

install-data-hook:
	for la in $(plugin_LTLIBRARIES) ; do rm -f $(DESTDIR)$(plugindir)/$$la ; done

EXTRA_DIST = plugins.vcxproj resource.h plugins.rc

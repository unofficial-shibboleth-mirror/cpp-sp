AUTOMAKE_OPTIONS = foreign

plugindir = $(libdir)/@PACKAGE_NAME@
plugin_LTLIBRARIES = adfs.la adfs-lite.la

adfs_la_LIBADD = $(XMLSEC_LIBS) \
	$(top_builddir)/shibsp/libshibsp.la

adfs_la_SOURCES = \
	adfs.cpp

adfs_lite_la_LIBADD = $(LITE_LIBS) \
	$(top_builddir)/shibsp/libshibsp-lite.la

adfs_lite_la_SOURCES = \
	adfs.cpp

adfs_la_LDFLAGS = -module -avoid-version
adfs_lite_la_LDFLAGS = -module -avoid-version
adfs_lite_la_CPPFLAGS = -DSHIBSP_LITE

install-data-hook:
	for la in $(plugin_LTLIBRARIES) ; do rm -f $(DESTDIR)$(plugindir)/$$la ; done

EXTRA_DIST = adfs.vcxproj adfs-lite.vcxproj resource.h adfs.rc

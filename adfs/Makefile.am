AUTOMAKE_OPTIONS = foreign

plugindir = $(libdir)/@PACKAGE_NAME@
plugin_LTLIBRARIES = adfs.la adfs-lite.la

adfs_la_CXXFLAGS = \
	$(opensaml_CFLAGS) \
	$(xmltooling_CFLAGS)
adfs_la_LIBADD = $(XMLSEC_LIBS) \
	$(top_builddir)/shibsp/libshibsp.la \
	$(opensaml_LIBS) \
	$(xmltooling_LIBS)

adfs_la_SOURCES = \
	adfs.cpp

adfs_lite_la_SOURCES = \
	adfs.cpp

adfs_la_LDFLAGS = -module -avoid-version
adfs_lite_la_LDFLAGS = -module -avoid-version
adfs_lite_la_CXXFLAGS = -DSHIBSP_LITE \
	$(xmltooling_lite_CFLAGS)
adfs_lite_la_LIBADD = $(top_builddir)/shibsp/libshibsp-lite.la \
	$(xmltooling_lite_LIBS)

EXTRA_DIST = resource.h adfs.rc

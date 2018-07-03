AUTOMAKE_OPTIONS = foreign

plugindir = $(libdir)/@PACKAGE_NAME@
plugin_LTLIBRARIES = adfs.la adfs-lite.la

adfs_la_CXXFLAGS = \
	$(BOOST_CPPFLAGS) \
	$(PTHREAD_CFLAGS) \
	$(opensaml_CFLAGS) \
	$(xmltooling_CFLAGS) \
	$(xerces_CFLAGS)
adfs_la_LIBADD = \
	$(top_builddir)/shibsp/libshibsp.la \
	$(PTHREAD_LIBS) \
	$(opensaml_LIBS) \
	$(xmltooling_LIBS) \
	$(xerces_LIBS)

adfs_la_SOURCES = \
	adfs.cpp

adfs_lite_la_SOURCES = \
	adfs.cpp

adfs_la_LDFLAGS = -module -avoid-version
adfs_lite_la_LDFLAGS = -module -avoid-version
adfs_lite_la_CXXFLAGS = -DSHIBSP_LITE \
	$(BOOST_CPPFLAGS) \
	$(PTHREAD_CFLAGS) \
	$(xmltooling_lite_CFLAGS) \
	$(xerces_CFLAGS) \
adfs_lite_la_LIBADD = $(top_builddir)/shibsp/libshibsp-lite.la \
	$(PTHREAD_LIBS) \
	$(xmltooling_lite_LIBS) \
	$(xerces_LIBS)

EXTRA_DIST = resource.h adfs.rc

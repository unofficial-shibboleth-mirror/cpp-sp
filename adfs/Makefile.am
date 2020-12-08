AUTOMAKE_OPTIONS = foreign

plugindir = $(libdir)/@PACKAGE_NAME@
plugin_LTLIBRARIES = adfs.la adfs-lite.la

adfs_la_CXXFLAGS = \
	$(AM_CXXFLAGS) \
	$(BOOST_CPPFLAGS) \
	$(PTHREAD_CFLAGS) \
	$(log4cpp_CFLAGS) \
	$(log4shib_CFLAGS) \
	$(opensaml_CFLAGS) \
	$(xmltooling_CFLAGS) \
	$(xerces_CFLAGS)
adfs_la_LIBADD = \
	$(top_builddir)/shibsp/libshibsp.la \
	$(PTHREAD_LIBS) \
	$(log4cpp_LIBS) \
	$(log4shib_LIBS) \
	$(opensaml_LIBS) \
	$(xmltooling_LIBS) \
	$(xerces_LIBS)
adfs_la_LDFLAGS = -module -avoid-version

adfs_la_SOURCES = \
	adfs.cpp

adfs_lite_la_SOURCES = \
	adfs.cpp

adfs_lite_la_CXXFLAGS = -DSHIBSP_LITE \
	$(AM_CXXFLAGS) \
	$(BOOST_CPPFLAGS) \
	$(PTHREAD_CFLAGS) \
	$(log4cpp_CFLAGS) \
	$(log4shib_CFLAGS) \
	$(xmltooling_lite_CFLAGS) \
	$(xerces_CFLAGS)
adfs_lite_la_LIBADD = $(top_builddir)/shibsp/libshibsp-lite.la \
	$(PTHREAD_LIBS) \
	$(log4cpp_LIBS) \
	$(log4shib_LIBS) \
	$(xmltooling_lite_LIBS) \
	$(xerces_LIBS)
adfs_lite_la_LDFLAGS = -module -avoid-version

EXTRA_DIST = resource.h adfs.rc

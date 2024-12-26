AUTOMAKE_OPTIONS = foreign subdir-objects

TESTS = shibsptest
check_PROGRAMS = shibsptest

shibsptest_CPPFLAGS = \
	$(BOOST_CPPFLAGS) -DSHIBSP_LITE

shibsptest_CXXFLAGS = \
	$(AM_CXXFLAGS)

shibsptest_SOURCES = \
	AgentTestSuite.cpp \
	AgentConfigTests.cpp \
	impl/XMLAccessControlTests.cpp \
	impl/XMLRequestMapperTests.cpp \
	util/PropertyTreeTests.cpp \
	util/BoostPropertySetTests.cpp \
	util/ReloadableXMLFileTests.cpp

shibsptest_LDADD = \
    $(top_builddir)/shibsp/libshibsp.la

EXTRA_DIST = data

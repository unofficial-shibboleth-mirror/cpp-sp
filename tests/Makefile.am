AUTOMAKE_OPTIONS = foreign subdir-objects

TESTS = shibsptest
check_PROGRAMS = shibsptest

shibsptest_CPPFLAGS = \
	$(BOOST_CPPFLAGS) -DSHIBSP_LITE

shibsptest_CXXFLAGS = \
	$(AM_CXXFLAGS)

noinst_HEADERS = \
	DummyRequest.h

shibsptest_SOURCES = \
	AgentTestSuite.cpp \
	AgentConfigTests.cpp \
	attribute/impl/DefaultAttributeConfigurationTests.cpp \
	impl/XMLAccessControlTests.cpp \
	impl/XMLRequestMapperTests.cpp \
	platform/iis/ModuleConfigTests.cpp \
	remoting/impl/SecretSourceTests.cpp \
	session/impl/MemorySessionCacheTests.cpp \
	session/impl/FilesystemSessionCacheTests.cpp \
	util/ISOParserTests.cpp \
	util/PropertyTreeTests.cpp \
	util/BoostPropertySetTests.cpp \
	util/ReloadableXMLFileTests.cpp

shibsptest_LDADD = \
    $(top_builddir)/shibsp/libshibsp.la

EXTRA_DIST = data

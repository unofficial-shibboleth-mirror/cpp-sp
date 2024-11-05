AUTOMAKE_OPTIONS = foreign subdir-objects

TESTS = shibsptest
check_PROGRAMS = shibsptest

shibsptest_CPPFLAGS = \
	$(BOOST_CPPFLAGS)

shibsptest_CXXFLAGS = \
	$(AM_CXXFLAGS)

shibsptest_SOURCES = \
	AgentTestSuite.cpp \
	PropertyTreeTests.cpp

shibsptest_LDADD = \
    $(top_builddir)/shibsp/libshibsp.la

EXTRA_DIST = data

AUTOMAKE_OPTIONS = foreign subdir-objects

if BUILD_UNITTEST
TESTS = shibsptest
check_PROGRAMS = shibsptest
endif

shibsptest_CXXFLAGS = \
    $(AM_CXXFLAGS) \
    $(CXXTESTFLAGS) \
    $(opensaml_CFLAGS) \
    $(xerces_CFLAGS) \
    $(xmltooling_CFLAGS)

shibsptest_h = \
    SPTest.h \
    DynamicMetadataProviderTest.h
    
noinst_HEADERS = \
    TestApplication.h \
    $(shibsptest_h)

nodist_shibsptest_SOURCES = $(shibsptest_h:.h=.cpp)
shibsptest_SOURCES = TestApplication.cpp

if BUILD_UNITTEST
BUILT_SOURCES = $(nodist_shibsptest_SOURCES)
CLEANFILES = $(nodist_shibsptest_SOURCES)
endif

do-cxxtestgen:
	if test "$(CPPFILE)" = "SPTest.cpp"; then \
		$(CXXTEST) --error-printer --have-eh --have-std --abort-on-fail -o $(CPPFILE) $(HFILE); \
	else \
		$(CXXTEST) --part --have-eh --have-std --abort-on-fail -o $(CPPFILE) $(HFILE); \
	fi;

$(nodist_shibsptest_SOURCES): %.cpp: %.h
	$(MAKE) do-cxxtestgen HFILE=$< CPPFILE=$@

shibsptest_LDADD = \
    $(top_builddir)/shibsp/libshibsp.la \
    $(opensaml_LIBS) \
    $(xerces_LIBS) \
    $(xmltooling_LIBS)

EXTRA_DIST = data

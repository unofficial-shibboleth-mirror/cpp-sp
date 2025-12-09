AUTOMAKE_OPTIONS = foreign subdir-objects

lib_LTLIBRARIES = libshibsp.la

libshibspincludedir = $(includedir)/shibsp

attrincludedir = $(includedir)/shibsp/attribute

handincludedir = $(includedir)/shibsp/handler

ioincludedir = $(includedir)/shibsp/io

logincludedir = $(includedir)/shibsp/logging

iisincludedir = $(includedir)/shibsp/platform/iis

remincludedir = $(includedir)/shibsp/remoting

sessionincludedir = $(includedir)/shibsp/session

utilincludedir = $(includedir)/shibsp/util

nodist_libshibspinclude_HEADERS = \
	config_pub.h \
	paths.h

libshibspinclude_HEADERS = \
	AbstractSPRequest.h \
	AccessControl.h \
	Agent.h \
	AgentConfig.h \
	base.h \
	exceptions.h \
	RequestMapper.h \
	SPRequest.h \
	version.h

attrinclude_HEADERS = \
	attribute/AttributeConfiguration.h

handinclude_HEADERS = \
	handler/AbstractHandler.h \
	handler/AssertionConsumerService.h \
	handler/Handler.h \
	handler/HandlerConfiguration.h \
	handler/SecuredHandler.h

ioinclude_HEADERS = \
	io/CookieManager.h \
	io/GenericRequest.h \
	io/GenericResponse.h \
	io/HTTPRequest.h \
	io/HTTPResponse.h

loginclude_HEADERS = \
	logging/Category.h \
	logging/LoggingService.h \
	logging/Priority.h

iisinclude_HEADERS = \
	platform/iis/ModuleConfig.h

reminclude_HEADERS = \
	remoting/ddf.h \
	remoting/RemotingService.h \
	remoting/SecretSource.h

sessioninclude_HEADERS = \
	session/AbstractSessionCache.h \
	session/SessionCache.h \
	session/SessionCacheSPI.h
	
utilinclude_HEADERS = \
	util/BoostPropertySet.h \
	util/CGIParser.h \
	util/Lockable.h \
	util/PathResolver.h \
	util/PluginManager.h \
	util/PropertySet.h \
	util/ReloadableXMLFile.h \
	util/SPConstants.h \
	util/URLEncoder.h

noinst_HEADERS = \
	internal.h \
	csprng/csprng.h \
	csprng/csprng.hpp \
	csprng/is_iterable.hpp \
	logging/impl/AbstractLoggingService.h \
	logging/impl/LoggingServiceSPI.h \
	logging/impl/StringUtil.h \
	remoting/impl/AbstractRemotingService.h \
	remoting/impl/AbstractHTTPRemotingService.h \
	util/Date.h \
	util/DirectoryWalker.h \
	util/IPRange.h \
	util/Misc.h

libshibsp_la_SOURCES = \
	AbstractSPRequest.cpp \
	Agent.cpp \
	exceptions.cpp \
	version.cpp \
	attribute/impl/DefaultAttributeConfiguration.cpp \
	csprng/impl/csprng.cpp \
	handler/impl/AbstractHandler.cpp \
	handler/impl/AttributeCheckerHandler.cpp \
	handler/impl/DefaultHandlerConfiguration.cpp \
	handler/impl/MetadataGenerator.cpp \
	handler/impl/Passthrough.cpp \
	handler/impl/SecuredHandler.cpp \
	handler/impl/SessionHandler.cpp \
	handler/impl/SessionInitiator.cpp \
	handler/impl/StatusHandler.cpp \
	handler/impl/TokenConsumer.cpp \
	impl/AgentConfig.cpp \
	impl/DefaultAgent.cpp \
	impl/XMLAccessControl.cpp \
	impl/XMLRequestMapper.cpp \
	io/impl/CookieManager.cpp \
	io/impl/HTTPRequest.cpp \
	io/impl/HTTPResponse.cpp \
	logging/impl/AbstractLoggingService.cpp \
	logging/impl/Category.cpp \
	logging/impl/ConsoleLoggingService.cpp \
	logging/impl/FileLoggingService.cpp \
	logging/impl/Priority.cpp \
	logging/impl/StringUtil.cpp \
	logging/impl/SyslogLoggingService.cpp \
	platform/iis/ModuleConfig.cpp \
	remoting/impl/ddf.cpp \
	remoting/impl/RemotingService.cpp \
	remoting/impl/AbstractRemotingService.cpp \
	remoting/impl/AbstractHTTPRemotingService.cpp \
	remoting/impl/SecretSource.cpp \
	remoting/impl/CurlHTTPRemotingService.cpp \
	session/impl/AbstractSessionCache.cpp \
	session/impl/FilesystemSessionCache.cpp \
	session/impl/MemorySessionCache.cpp \
	session/impl/StorageServiceSessionCache.cpp \
	util/BoostPropertySet.cpp \
	util/CGIParser.cpp \
	util/DirectoryWalker.cpp \
	util/IPRange.cpp \
	util/Misc.cpp \
	util/PathResolver.cpp \
	util/ReloadableXMLFile.cpp \
	util/SPConstants.cpp \
	util/URLEncoder.cpp


# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
libshibsp_la_LDFLAGS = -version-info 13:0:0 $(BOOST_REGEX_LDFLAGS) $(BOOST_REGEX_LDPATH)
libshibsp_la_CXXFLAGS = -DSHIBSP_LITE \
    $(AM_CXXFLAGS) \
    $(BOOST_CPPFLAGS) \
    $(PTHREAD_CFLAGS) \
    $(libcurl_CFLAGS)
libshibsp_la_LIBADD = \
    $(PTHREAD_LIBS) \
    $(libcurl_LIBS) \
    $(BOOST_REGEX_LIBS)

pkgsysconfdir = $(sysconfdir)/@PACKAGE_NAME@
logdir = ${localstatedir}/log
rundir = $(localstatedir)/run
cachedir = $(localstatedir)/cache

paths.h: ${srcdir}/paths.h.in Makefile ${top_builddir}/config.status
	rm -f $@.tmp
	sed < ${srcdir}/$@.in > $@.tmp \
		-e 's:@-PREFIX-@:${prefix}:g' \
		-e 's:@-LIBDIR-@:${libdir}:g' \
		-e 's:@-SYSCONFDIR-@:${sysconfdir}:g' \
		-e 's:@-LOGDIR-@:${logdir}:g' \
		-e 's:@-RUNDIR-@:${rundir}:g' \
		-e 's:@-CACHEDIR-@:${cachedir}:g' \
		-e 's:@-PKGSYSCONFDIR-@:${pkgsysconfdir}:g'
	cmp -s $@ $@.tmp || mv $@.tmp $@
	rm -f $@.tmp

EXTRA_DIST = \
	config_pub.h.in \
	config_pub_win32.h\
	paths.h.in \
	resource.h \
	shibsp.rc \
	logging/impl/WindowsLoggingService.cpp \
	remoting/impl/WinHTTPRemotingService.cpp

BUILT_SOURCES = paths.h

CLEANFILES = paths.h

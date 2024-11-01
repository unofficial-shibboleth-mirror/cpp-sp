AUTOMAKE_OPTIONS = foreign subdir-objects

lib_LTLIBRARIES = libshibsp.la

libshibspincludedir = $(includedir)/shibsp

attrincludedir = $(includedir)/shibsp/attribute

handincludedir = $(includedir)/shibsp/handler

liteincludedir = $(includedir)/shibsp/lite

remincludedir = $(includedir)/shibsp/remoting

utilincludedir = $(includedir)/shibsp/util

nodist_libshibspinclude_HEADERS = \
	config_pub.h \
	paths.h

libshibspinclude_HEADERS = \
	AbstractSPRequest.h \
	AccessControl.h \
	Application.h \
	base.h \
	exceptions.h \
	RequestMapper.h \
	ServiceProvider.h \
	SessionCache.h \
	SPConfig.h \
	SPRequest.h \
	version.h

attrinclude_HEADERS = \
	attribute/Attribute.h \
	attribute/BinaryAttribute.h \
	attribute/ScopedAttribute.h \
	attribute/SimpleAttribute.h

handinclude_HEADERS = \
	handler/AbstractHandler.h \
	handler/AssertionConsumerService.h \
	handler/Handler.h \
	handler/LogoutHandler.h \
	handler/LogoutInitiator.h \
	handler/RemotedHandler.h \
	handler/SecuredHandler.h \
	handler/SessionInitiator.h

liteinclude_HEADERS = \
	lite/CommonDomainCookie.h \
	lite/SAMLConstants.h

reminclude_HEADERS = \
	remoting/ddf.h \
	remoting/ListenerService.h
	
utilinclude_HEADERS = \
	util/CGIParser.h \
	util/DOMPropertySet.h \
	util/IPRange.h \
	util/PropertySet.h \
	util/SPConstants.h \
	util/TemplateParameters.h

noinst_HEADERS = \
	internal.h \
	impl/StoredSession.h \
	impl/StorageServiceSessionCache.h \
	impl/XMLApplication.h \
	impl/XMLServiceProvider.h \
	remoting/impl/SocketListener.h

libshibsp_la_SOURCES = \
	AbstractSPRequest.cpp \
	Application.cpp \
	ServiceProvider.cpp \
	SPConfig.cpp \
	version.cpp \
	attribute/Attribute.cpp \
	attribute/BinaryAttribute.cpp \
	attribute/SimpleAttribute.cpp \
	attribute/ScopedAttribute.cpp \
	handler/impl/AbstractHandler.cpp \
	handler/impl/AdminLogoutInitiator.cpp \
	handler/impl/AssertionConsumerService.cpp \
	handler/impl/AssertionLookup.cpp \
	handler/impl/AttributeCheckerHandler.cpp \
	handler/impl/ChainingLogoutInitiator.cpp \
	handler/impl/ChainingSessionInitiator.cpp \
	handler/impl/CookieSessionInitiator.cpp \
	handler/impl/DiscoveryFeed.cpp \
	handler/impl/ExternalAuthHandler.cpp \
	handler/impl/FormSessionInitiator.cpp \
	handler/impl/LocalLogoutInitiator.cpp \
	handler/impl/LogoutHandler.cpp \
	handler/impl/LogoutInitiator.cpp \
	handler/impl/MetadataGenerator.cpp \
	handler/impl/RemotedHandler.cpp \
	handler/impl/SAML1Consumer.cpp \
	handler/impl/SAML2Consumer.cpp \
	handler/impl/SAML2ArtifactResolution.cpp \
	handler/impl/SAML2Logout.cpp \
	handler/impl/SAML2LogoutInitiator.cpp \
	handler/impl/SAML2NameIDMgmt.cpp \
	handler/impl/SAML2SessionInitiator.cpp \
	handler/impl/SAMLDSSessionInitiator.cpp \
	handler/impl/SecuredHandler.cpp \
	handler/impl/SessionHandler.cpp \
	handler/impl/SessionInitiator.cpp \
	handler/impl/Shib1SessionInitiator.cpp \
	handler/impl/StatusHandler.cpp \
	handler/impl/TransformSessionInitiator.cpp \
	handler/impl/WAYFSessionInitiator.cpp \
	impl/ChainingAccessControl.cpp \
	impl/StoredSession.cpp \
	impl/StorageServiceSessionCache.cpp \
	impl/XMLAccessControl.cpp \
	impl/XMLApplication.cpp \
	impl/XMLRequestMapper.cpp \
	impl/XMLServiceProvider.cpp \
	lite/CommonDomainCookie.cpp \
	lite/SAMLConstants.cpp \
	remoting/impl/ddf.cpp \
	remoting/impl/ListenerService.cpp \
	remoting/impl/SocketListener.cpp \
	remoting/impl/TCPListener.cpp \
	remoting/impl/UnixListener.cpp \
	util/CGIParser.cpp \
	util/DOMPropertySet.cpp \
	util/IPRange.cpp \
	util/SPConstants.cpp \
	util/TemplateParameters.cpp


# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
libshibsp_la_LDFLAGS = -version-info 13:0:0
libshibsp_la_CXXFLAGS = -DSHIBSP_LITE \
    $(AM_CXXFLAGS) \
    $(BOOST_CPPFLAGS) \
    $(PTHREAD_CFLAGS) \
    $(gss_CFLAGS) $(gnu_gss_CFLAGS) \
    $(log4shib_CFLAGS) $(log4cpp_CFLAGS) \
    $(xerces_CFLAGS) \
    $(xmltooling_lite_CFLAGS)
libshibsp_la_LIBADD = \
    $(PTHREAD_LIBS) \
    $(gss_LIBS) $(gnu_gss_LIBS) \
    $(log4shib_LIBS) $(log4cpp_LIBS) \
    $(xerces_LIBS) \
    $(xmltooling_lite_LIBS)

pkgsysconfdir = $(sysconfdir)/@PACKAGE_NAME@
pkgxmldir = $(datadir)/xml/@PACKAGE_NAME@
logdir = ${localstatedir}/log
rundir = $(localstatedir)/run
cachedir = $(localstatedir)/cache
xmldir = $(datadir)/xml

paths.h: ${srcdir}/paths.h.in Makefile ${top_builddir}/config.status
	rm -f $@.tmp
	sed < ${srcdir}/$@.in > $@.tmp \
		-e 's:@-PREFIX-@:${prefix}:g' \
		-e 's:@-LIBDIR-@:${libdir}:g' \
		-e 's:@-SYSCONFDIR-@:${sysconfdir}:g' \
		-e 's:@-LOGDIR-@:${logdir}:g' \
		-e 's:@-RUNDIR-@:${rundir}:g' \
		-e 's:@-CACHEDIR-@:${cachedir}:g' \
		-e 's:@-XMLDIR-@:${xmldir}:g' \
		-e 's:@-PKGSYSCONFDIR-@:${pkgsysconfdir}:g' \
		-e 's:@-PKGXMLDIR-@:${pkgxmldir}:g' \
		-e 's:@-XMLTOOLINGXMLDIR-@:${XMLTOOLINGXMLDIR}:g' \
		-e 's:@-OPENSAMLXMLDIR-@:${OPENSAMLXMLDIR}:g'
	cmp -s $@ $@.tmp || mv $@.tmp $@
	rm -f $@.tmp

EXTRA_DIST = \
	config_pub.h.in \
	config_pub_win32.h\
	paths.h.in \
	resource.h \
	shibsp.rc

BUILT_SOURCES = paths.h

CLEANFILES = paths.h

AUTOMAKE_OPTIONS = foreign

pkgsysconfdir = $(sysconfdir)/@PACKAGE@
xmldir = $(datadir)/xml

lib_LTLIBRARIES = libshibsp.la libshibsp-lite.la

libshibspincludedir = $(includedir)/shibsp

attrincludedir = $(includedir)/shibsp/attribute

attrresincludedir = $(includedir)/shibsp/attribute/resolver

bindincludedir = $(includedir)/shibsp/binding

handincludedir = $(includedir)/shibsp/handler

mdincludedir = $(includedir)/shibsp/metadata

remincludedir = $(includedir)/shibsp/remoting

secincludedir = $(includedir)/shibsp/security

utilincludedir = $(includedir)/shibsp/util

libshibspinclude_HEADERS = \
	AbstractSPRequest.h \
	AccessControl.h \
	Application.h \
	base.h \
	exceptions.h \
	paths.h \
	RequestMapper.h \
	ServiceProvider.h \
	SessionCache.h \
	SPConfig.h \
	SPRequest.h \
	TransactionLog.h \
	version.h

attrinclude_HEADERS = \
	attribute/Attribute.h \
	attribute/AttributeDecoder.h \
	attribute/NameIDAttribute.h \
	attribute/ScopedAttribute.h \
	attribute/SimpleAttribute.h

attrfiltinclude_HEADERS = \
	attribute/filtering/AttributeFilter.h \
	attribute/filtering/BasicFilteringContext.h \
	attribute/filtering/FilteringContext.h \
	attribute/filtering/FilterPolicyContext.h \
	attribute/filtering/MatchFunctor.h

attrresinclude_HEADERS = \
	attribute/resolver/AttributeExtractor.h \
	attribute/resolver/AttributeResolver.h \
	attribute/resolver/ResolutionContext.h

bindinclude_HEADERS = \
	binding/ArtifactResolver.h \
	binding/SOAPClient.h

handinclude_HEADERS = \
	handler/AbstractHandler.h \
	handler/AssertionConsumerService.h \
	handler/Handler.h \
	handler/RemotedHandler.h \
	handler/SessionInitiator.h

liteinclude_HEADERS = \
	lite/CGIParser.h \
	lite/CommonDomainCookie.h \
	lite/SAMLConstants.h

mdinclude_HEADERS = \
	metadata/MetadataExt.h

reminclude_HEADERS = \
	remoting/ddf.h \
	remoting/ListenerService.h
	
secinclude_HEADERS = \
	security/PKIXTrustEngine.h \
	security/SecurityPolicy.h

utilinclude_HEADERS = \
	util/DOMPropertySet.h \
	util/PropertySet.h \
	util/SPConstants.h \
	util/TemplateParameters.h

noinst_HEADERS = \
	internal.h \
	remoting/impl/SocketListener.h

common_sources = \
	AbstractSPRequest.cpp \
	Application.cpp \
	ServiceProvider.cpp \
	SessionCache.cpp \
	SPConfig.cpp \
	attribute/Attribute.cpp \
	handler/impl/AbstractHandler.cpp \
	handler/impl/AssertionConsumerService.cpp \
	handler/impl/ChainingSessionInitiator.cpp \
	handler/impl/RemotedHandler.cpp \
	handler/impl/SAML1Consumer.cpp \
	handler/impl/SAML2Consumer.cpp \
	handler/impl/SAML2SessionInitiator.cpp \
	handler/impl/SAMLDSSessionInitiator.cpp \
	handler/impl/SessionInitiator.cpp \
	handler/impl/Shib1SessionInitiator.cpp \
	handler/impl/WAYFSessionInitiator.cpp \
	impl/XMLAccessControl.cpp \
	impl/XMLRequestMapper.cpp \
	impl/XMLServiceProvider.cpp \
	remoting/impl/ddf.cpp \
	remoting/impl/ListenerService.cpp \
	remoting/impl/SocketListener.cpp \
	remoting/impl/TCPListener.cpp \
	remoting/impl/UnixListener.cpp \
	util/DOMPropertySet.cpp \
	util/SPConstants.cpp \
	util/TemplateParameters.cpp

libshibsp_lite_la_SOURCES = \
	${common_sources} \
	impl/RemotedSessionCache.cpp \
	lite/CGIParser.cpp \
	lite/CommonDomainCookie.cpp \
	lite/SAMLConstants.cpp

libshibsp_la_SOURCES = \
	${common_sources} \
	attribute/NameIDAttributeDecoder.cpp \
	attribute/ScopedAttributeDecoder.cpp \
	attribute/StringAttributeDecoder.cpp \
	attribute/filtering/AttributeFilter.cpp \
	attribute/filtering/ChainingAttributeFilter.cpp \
	attribute/filtering/XMLAttributeFilter.cpp \
	attribute/filtering/MatchFunctor.cpp \
	attribute/filtering/AndMatchFunctor.cpp \
	attribute/filtering/AnyMatchFunctor.cpp \
	attribute/filtering/NotMatchFunctor.cpp \
	attribute/filtering/OrMatchFunctor.cpp \
	attribute/filtering/AttributeIssuerStringFunctor.cpp \
	attribute/filtering/AttributeRequesterStringFunctor.cpp \
	attribute/filtering/AttributeScopeStringFunctor.cpp \
	attribute/filtering/AttributeValueStringFunctor.cpp \
	attribute/filtering/AuthenticationMethodStringFunctor.cpp \
	attribute/filtering/AttributeIssuerRegexFunctor.cpp \
	attribute/filtering/AttributeRequesterRegexFunctor.cpp \
	attribute/filtering/AttributeScopeRegexFunctor.cpp \
	attribute/filtering/AttributeValueRegexFunctor.cpp \
	attribute/filtering/AuthenticationMethodRegexFunctor.cpp \
	attribute/filtering/NumberOfAttributeValuesFunctor.cpp \
	attribute/filtering/AttributeIssuerInEntityGroupFunctor.cpp \
	attribute/filtering/AttributeRequesterInEntityGroupFunctor.cpp \
	attribute/filtering/AttributeScopeMatchesShibMDScopeFunctor.cpp \
	attribute/resolver/impl/ChainingAttributeResolver.cpp \
	attribute/resolver/impl/QueryAttributeResolver.cpp \
	attribute/resolver/impl/XMLAttributeExtractor.cpp \
	binding/impl/ArtifactResolver.cpp \
	binding/impl/SOAPClient.cpp \
	impl/StorageServiceSessionCache.cpp \
	metadata/MetadataExtImpl.cpp \
	metadata/MetadataExtSchemaValidators.cpp \
	security/PKIXTrustEngine.cpp \
	security/SecurityPolicy.cpp

# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
libshibsp_la_LDFLAGS = $(XMLSEC_LIBS) -version-info 1:0:0
libshibsp_lite_la_LDFLAGS = -version-info 1:0:0
libshibsp_lite_la_CPPFLAGS = -DSHIBSP_LITE

paths.h: ${srcdir}/paths.h.in Makefile ${top_builddir}/config.status
	rm -f $@.tmp
	sed < ${srcdir}/$@.in > $@.tmp \
	    -e 's:@-PKGSYSCONFDIR-@:${pkgsysconfdir}:' \
	    -e 's:@-XMLDIR-@:${xmldir}:'
	cmp -s $@ $@.tmp || mv $@.tmp $@
	rm -f $@.tmp

install-exec-hook:
	for la in $(lib_LTLIBRARIES) ; do rm -f $(DESTDIR)$(libdir)/$$la ; done

EXTRA_DIST = shibsp.vcproj shibsp-lite.vcproj paths.h.in resource.h shibsp.rc
BUILT_SOURCES = paths.h

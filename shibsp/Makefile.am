AUTOMAKE_OPTIONS = foreign

pkgsysconfdir = $(sysconfdir)/@PACKAGE@
xmldir = $(datadir)/xml

lib_LTLIBRARIES = libshibsp.la

libshibspincludedir = $(includedir)/shibsp

attrincludedir = $(includedir)/shibsp/attribute

mdincludedir = $(includedir)/shibsp/metadata

remincludedir = $(includedir)/shibsp/remoting

secincludedir = $(includedir)/shibsp/security

utilincludedir = $(includedir)/shibsp/util

libshibspinclude_HEADERS = \
	AbstractHandler.h \
	AbstractSPRequest.h \
	AccessControl.h \
	Application.h \
	base.h \
	exceptions.h \
	Handler.h \
	paths.h \
	RequestMapper.h \
	ServiceProvider.h \
	SessionCache.h \
	SPConfig.h \
	SPRequest.h \
	version.h

attrinclude_HEADERS = \
	attribute/Attribute.h \
	attribute/NameIDAttribute.h \
	attribute/ScopedAttribute.h \
	attribute/SimpleAttribute.h

mdinclude_HEADERS = \
	metadata/MetadataExt.h

reminclude_HEADERS = \
	ddf.h \
	ListenerService.h
	
secinclude_HEADERS = \
	security/PKIXTrustEngine.h

utilinclude_HEADERS = \
	util/DOMPropertySet.h \
	util/PropertySet.h \
	util/SPConstants.h \
	util/TemplateParameters.h

noinst_HEADERS = \
	internal.h \
	remoting/impl/SocketListener.h

libshibsp_la_SOURCES = \
	AbstractHandler.cpp \
	AbstractSPRequest.cpp \
	Application.cpp \
	ServiceProvider.cpp \
	SessionCache.cpp \
	SPConfig.cpp \
	impl/RemotedSessionCache.cpp \
	impl/StorageServiceSessionCache.cpp \
	impl/XMLAccessControl.cpp \
	impl/XMLRequestMapper.cpp \
	metadata/MetadataExtImpl.cpp \
	metadata/MetadataExtSchemaValidators.cpp \
	remoting/impl/ddf.cpp \
	remoting/impl/ListenerService.cpp \
	remoting/impl/SocketListener.cpp \
	remoting/impl/TCPListener.cpp \
	remoting/impl/UnixListener.cpp \
	security/PKIXTrustEngine.cpp \
	util/DOMPropertySet.cpp \
	util/SPConstants.cpp \
	util/TemplateParameters.cpp

# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
libshibsp_la_LDFLAGS = -version-info 1:0:0

paths.h: ${srcdir}/paths.h.in Makefile ${top_builddir}/config.status
	rm -f $@.tmp
	sed < ${srcdir}/$@.in > $@.tmp \
	    -e 's:@-PKGSYSCONFDIR-@:${pkgsysconfdir}:' \
	    -e 's:@-XMLDIR-@:${xmldir}:'
	cmp -s $@ $@.tmp || mv $@.tmp $@
	rm -f $@.tmp

install-exec-hook:
	for la in $(lib_LTLIBRARIES) ; do rm -f $(DESTDIR)$(libdir)/$$la ; done

EXTRA_DIST = shibsp.vcproj paths.h.in resource.h shibsp.rc
BUILT_SOURCES = paths.h

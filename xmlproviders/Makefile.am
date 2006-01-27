## $Id: Makefile.am,v 1.19 2004/01/18 00:16:19 cantor Exp $

AUTOMAKE_OPTIONS = foreign

plugindir = $(libexecdir)
plugin_LTLIBRARIES = xmlproviders.la

noinst_HEADERS = internal.h

xmlproviders_la_LIBADD = \
	$(top_builddir)/shib/libshib.la \
	$(top_builddir)/shib-target/libshib-target.la

xmlproviders_la_SOURCES = \
	CredResolvers.cpp \
	TargetedID.cpp \
	XML.cpp \
	XMLAAP.cpp \
	XMLAccessControl.cpp \
	XMLCredentials.cpp \
	XMLMetadata.cpp \
	XMLProviders.cpp \
	XMLTrust.cpp


xmlproviders_la_LDFLAGS = -module -avoid-version

install-exec-hook:
	for la in $(plugin_LTLIBRARIES) ; do rm -f $(DESTDIR)$(plugindir)/$$la ; done

EXTRA_DIST = xmlproviders.vcproj resource.h xmlproviders.rc


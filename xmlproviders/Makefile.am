## $Id: Makefile.am,v 1.19 2004/01/18 00:16:19 cantor Exp $

AUTOMAKE_OPTIONS = foreign

plugindir = $(libexecdir)
plugin_LTLIBRARIES = xmlproviders.la

noinst_HEADERS = internal.h

xmlproviders_la_LIBADD = \
	../shib/libshib.la

xmlproviders_la_SOURCES = \
                    CredResolvers.cpp \
                    ScopedAttribute.cpp \
                    XML.cpp \
                    XMLAAP.cpp \
                    XMLCredentials.cpp \
                    XMLMetadata.cpp \
                    XMLProviders.cpp \
                    XMLRevocation.cpp \
                    XMLTrust.cpp


xmlproviders_la_LDFLAGS = -module -avoid-version

EXTRA_DIST = xmlproviders.dsp


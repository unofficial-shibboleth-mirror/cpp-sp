## $Id$

AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libshib.la

libshibdir = $(includedir)/shib
libshib_HEADERS = shib.h shib-threads.h
noinst_HEADERS = internal.h

libshib_la_SOURCES = \
                    AAP.cpp \
                    ClubShibPOSTProfile.cpp \
                    Constants.cpp \
                    Metadata.cpp \
                    SAMLBindingFactory.cpp \
                    ShibConfig.cpp \
                    ShibPOSTProfile.cpp \
                    ShibPOSTProfileFactory.cpp \
                    ShibSOAPBinding.cpp \
                    ScopedAttribute.cpp \
                    SimpleAttribute.cpp \
                    XML.cpp \
                    XMLMetadata.cpp \
                    XMLTrust.cpp \
                    XMLCredentials.cpp \
                    shib-threads.cpp


# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
libshib_la_LDFLAGS = -version-info 5:0:0

EXTRA_DIST = shib.dsp shib-threads-win32.cpp


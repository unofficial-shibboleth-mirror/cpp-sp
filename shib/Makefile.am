## $Id$

AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libshib.la

libshibdir = $(includedir)/shib
libshib_HEADERS = shib.h

libshib_la_SOURCES = \
                    ClubShibPOSTProfile.cpp \
                    Constants.cpp \
                    SAMLBindingFactory.cpp \
                    ShibConfig.cpp \
                    ShibPOSTProfile.cpp \
                    ShibPOSTProfileFactory.cpp \
                    XML.cpp \
                    XMLOriginSiteMapper.cpp

# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
libshib_la_LDFLAGS = -version-info 1:0:0


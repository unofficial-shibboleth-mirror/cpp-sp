## $Id$

AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libeduPerson.la

libeduPersondir = $(includedir)/shib
libeduPerson_HEADERS = eduPerson.h

libeduPerson_la_SOURCES = \
                    eduPerson.cpp \
                    Constants.cpp \
                    AffiliationAttribute.cpp \
                    EPPNAttribute.cpp \
                    EntitlementAttribute.cpp \
                    PrimaryAffiliationAttribute.cpp \
                    ScopedAttribute.cpp

# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
libeduPerson_la_LDFLAGS = -version-info 1:0:0


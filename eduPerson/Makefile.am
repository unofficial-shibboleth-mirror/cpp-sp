## $Id$

AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libeduPerson.la

libeduPersondir = $(includedir)/eduPerson
libeduPerson_HEADERS = eduPerson.h
noinst_HEADERS = internal.h

libeduPerson_la_LIBADD = $(top_builddir)/shib/libshib.la $(top_builddir)/shib-target/libshib-target.la

libeduPerson_la_SOURCES = \
                    eduPerson.cpp \
                    Constants.cpp \
                    AAP.cpp \
                    AffiliationAttribute.cpp \
                    EPPNAttribute.cpp \
                    EntitlementAttribute.cpp \
                    ScopedAttribute.cpp \
                    SimpleAttribute.cpp

# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
libeduPerson_la_LDFLAGS = -version-info 2:0:0


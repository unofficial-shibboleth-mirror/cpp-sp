## $Id$

AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libshib-target.la

if USE_OUR_ONCRPC
libshib_target_la_LIBADD = ${top_builddir}/oncrpc/liboncrpc.la
AM_CFLAGS = -I${top_srcdir}/oncrpc
AM_CXXFLAGS = -I${top_srcdir}/oncrpc
endif

libshib_targetdir = $(includedir)/shib-target
libshib_target_HEADERS = shib-target.h shibrpc.h ccache-utils.h

libshib_target_la_SOURCES = \
	shib-ccache.cpp \
	shib-config.cpp \
	shib-ini.cpp \
	shib-mlp.cpp \
	shib-resource.cpp \
	shib-resourceentry.cpp \
	shib-rm.cpp \
	shib-rpcerror.cpp \
	shib-rpchandle.cpp \
	shib-rpcutil.c \
	shib-shire.cpp \
	shib-sock.c \
	shib-target.cpp \
	shibrpc-clnt.c \
	shibrpc-server.cpp \
	shibrpc-svc.c \
	shibrpc-xdr.c

# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
libshib_target_la_LDFLAGS = -version-info 3:1:0



RPCGEN=rpcgen -M
RPCGEN_SRC=shibrpc.x

very-clean: 
	$(RM) shibrpc.h shibrpc-xdr.c shibrpc-clnt.c shibrpc-svc.c

rpcgen:
	$(MAKE) do_rpcgen RPCGEN_TARGET=shibrpc.h RPCGEN_ARGS=-h
	$(MAKE) do_rpcgen RPCGEN_TARGET=shibrpc-xdr.c RPCGEN_ARGS=-c
	$(MAKE) do_rpcgen RPCGEN_TARGET=shibrpc-clnt.c RPCGEN_ARGS=-l
	$(MAKE) do_rpcgen RPCGEN_TARGET=shibrpc-svc.c RPCGEN_ARGS=-m
	$(MAKE) do_rpcgen RPCGEN_TARGET=shibrpc-server-stubs.c RPCGEN_ARGS=-Ss

do_rpcgen:
	$(RM) $(RPCGEN_TARGET)
	$(RPCGEN) $(RPCGEN_ARGS) -o $(RPCGEN_TARGET) $(RPCGEN_SRC)

dnl $Id$ 

AC_PREREQ([2.50])
AC_INIT([shibboleth], [0.1], [mace-shib-users@internet2.edu], [shibboleth])
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE

sinclude(acx_pthread.m4)

AC_PROG_CC([gcc3 gcc cc])
AC_PROG_CXX([g++3 g++ c++ CC])
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_LANG(C++)

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_STRFTIME
AC_CHECK_FUNCS([strchr strdup strstr gmtime_r])
AC_CHECK_HEADERS([dlfcn.h])

# C++ requirements
AC_CXX_REQUIRE_STL
AC_CXX_NAMESPACES

# checks for pthreads
ACX_PTHREAD([enable_threads="pthread"],[enable_threads="no"])
if test $enable_threads != "pthread"; then
    AC_MSG_ERROR([unable to find pthreads, currently this is required])
else
    AC_DEFINE(HAVE_PTHREAD,1,[Define if you have POSIX threads libraries and header files.])
    LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$PTHREAD_CFLAGS $CFLAGS"
    CXXFLAGS="$PTHREAD_CFLAGS $CXXFLAGS"
fi

AC_ARG_WITH(xerces, 
            AC_HELP_STRING([--with-xerces=PATH], [where xerces-c is installed]),
            [if test x_$with_xerces != x_/usr; then
                LDFLAGS="-L${with_xerces}/lib $LDFLAGS"
                CPPFLAGS="-I${with_xerces}/include $CPPFLAGS"
            fi])


AC_ARG_WITH(openssl, 
            AC_HELP_STRING([--with-openssl=PATH], [where openssl is installed]),
            [if test x_$with_openssl != x_/usr; then
                LDFLAGS="-L${with_openssl}/lib $LDFLAGS"
                CPPFLAGS="-I${with_openssl}/include $CPPFLAGS"
            fi])

AC_ARG_WITH(log4cpp, 
            AC_HELP_STRING([--with-log4cpp=PATH], [where log4cpp is installed]),
            [if test x_$with_log4cpp != x_/usr; then
                LDFLAGS="-L${with_log4cpp}/lib $LDFLAGS"
                CPPFLAGS="-I${with_log4cpp}/include $CPPFLAGS"
            fi])

AC_ARG_WITH(saml,
            AC_HELP_STRING([--with-saml=PATH], [where saml is installed]),
            [if test x_$with_saml != x_/usr; then
                LDFLAGS="-L${with_saml}/lib $LDFLAGS"
                CPPFLAGS="-I${with_saml}/include $CPPFLAGS"
            fi])

AC_CHECK_HEADER([xercesc/dom/DOM.hpp],,
                AC_MSG_ERROR([unable to find xerces header files]))
saved_LIBS="$LIBS"
LIBS="-lxerces-c $LIBS"
AC_TRY_LINK(
	[#include <xercesc/util/PlatformUtils.hpp>],
        [XMLPlatformUtils::Initialize()],
	[AC_DEFINE(HAVE_LIBXERCESC,1,[Define if Xerces-C library was found])],
	[AC_MSG_ERROR([unable to link with Xerces])
		LIBS="$saved_LIBS"
	])

AC_CHECK_HEADER([openssl/ssl.h],,
                AC_MSG_ERROR([unable to find openssl header files]))
AC_CHECK_LIB([crypto], [ERR_load_CRYPTO_strings],,
             AC_MSG_ERROR([unable to link with openssl libraries]))
AC_CHECK_LIB([ssl], [SSL_library_init],, 
             AC_MSG_ERROR([unable to link with openssl libraries]))

AC_CHECK_HEADER([log4cpp/Category.hh],,
                AC_MSG_ERROR([unable to find log4cpp header files]))

AC_CHECK_HEADER([saml/saml.h],,
                AC_MSG_ERROR([unable to find saml header files]))

saved_LIBS="$LIBS"
LIBS="-llog4cpp $LIBS"
AC_TRY_LINK(
	[#include <log4cpp/Category.hh>],
	[log4cpp::Category::getInstance("foo")],
	[AC_DEFINE(HAVE_LIBLOG4CPP,1,[Define if log4cpp library was found])],
	[AC_MSG_ERROR([unable to link with log4cpp])
		LIBS="$saved_LIBS"
	])

saved_LIBS="$LIBS"
LIBS="-lsaml $LIBS"
AC_TRY_LINK(
        [#include <saml/saml.h>],
        [saml::SAMLConfig::getConfig()],
        [AC_DEFINE(HAVE_SAML,1,[Define if saml library was found])],
        [AC_MSG_ERROR([unable to link with saml])
                LIBS="$saved_LIBS"
        ])

# output makefiles
AC_OUTPUT(Makefile shib/Makefile schemas/Makefile eduPerson/Makefile \
		   shib-target/Makefile test/Makefile)


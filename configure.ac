dnl $Id$ 

AC_PREREQ([2.50])
AC_INIT([shibboleth], [0.1], [mace-shib-users@internet2.edu], [shibboleth])
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE(shibboleth, 0.1)

sinclude(acx_pthread.m4)
sinclude(acx_rpctest.m4)

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


# old_LIBS="$LIBS"
# AC_SEARCH_LIBS(xdr_uint64_t,nsl,,
# 	[CFLAGS="$CFLAGS -DNEED_XDR_LONGLONG"
# 	 CXXFLAGS="$CXXFLAGS -DNEED_XDR_LONGLONG"])
# LIBS="$old_LIBS"

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

# Test RPC now -- deal with it later
ACX_RPCTEST([rpctest="yes"],[rpctest="no"])

AC_ARG_WITH(dmalloc,
            AC_HELP_STRING([--with-dmalloc=PATH], [where dmalloc is installed]),
            [if test x_$with_dmalloc != x_/usr; then
                LDFLAGS="-L${with_dmalloc}/lib $LDFLAGS"
                CPPFLAGS="-I${with_dmalloc}/include $CPPFLAGS"
            fi
	    AC_CHECK_LIB(dmallocxx, dmalloc_shutdown,,
		         AC_MSG_ERROR([unable to find dmallocxx library]))
	    ])

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

AC_ARG_WITH(xmlsec,
            AC_HELP_STRING([--with-xmlsec=PATH], [where xmlsec is installed]),
            [if test -f "${with_xmlsec}/bin/xmlsec-config"; then
                LDFLAGS="`${with_xmlsec}/bin/xmlsec-config --libs` $LDFLAGS"
                CPPFLAGS="`${with_xmlsec}/bin/xmlsec-config --cflags` $CPPFLAGS"
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

AC_CHECK_HEADER([libxml/parser.h],,
                AC_MSG_ERROR([unable to find libxml2 header files]))
AC_CHECK_LIB([xml2], [xmlInitParser],echo "foo" > /dev/null,
             AC_MSG_ERROR([unable to link with libxml2]))

AC_CHECK_HEADER([xmlsec/xmlsec.h],,
                AC_MSG_ERROR([unable to find xmlsec header files]))
AC_CHECK_LIB([xmlsec], [xmlSecInit],echo "foo" > /dev/null,
             AC_MSG_ERROR([unable to link with xmlsec]))

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

# output the underlying makefiles
WANT_SUBDIRS="shib schemas configs eduPerson shib-target shar test"
AC_CONFIG_FILES([Makefile shib/Makefile schemas/Makefile eduPerson/Makefile \
		 configs/Makefile oncrpc/Makefile oncrpc/rpc/Makefile \
		 shib-target/Makefile shar/Makefile test/Makefile])

# now deal with the rpc library, to see if we need to build our own
if test $rpctest = "no"; then
    WANT_SUBDIRS="oncrpc $WANT_SUBDIRS"
fi
AM_CONDITIONAL(USE_OUR_ONCRPC,test "$rpctest" = "no")

# Much of this is taken from mod_dav.
# The basic idea is to use configure options to control whether/which types
# of web server modules get built. We assume there may eventually be multiple
# types (Apache 1/2, iPlanet, others).

# Apache 1.3 (mod_shire/mod_shibrm)
#   --with-apache   (static build, no idea how to do this yet, so not supported)
#   --with-apxs     (DSO build, the normal way, uses apxs to derive build flags)
#   --without-apxs  (DSO build, you tell us how to build using the environment)

AC_MSG_CHECKING([for dynamic Apache module support (w/ or w/o APXS)])
AC_ARG_WITH(apxs,
[  --with-apxs[=FILE]        Build shared Apache module(s). FILE is the optional
                          pathname to the Apache apxs tool; defaults to "apxs".],
[
    if test "$withval" = "yes"; then
      for i in /usr/sbin /usr/local/apache/bin ; do
        if test -f "$i/apxs"; then
          APXS="$i/apxs"
        fi
      done
      if test -z "$APXS"; then
        APXS=apxs
      fi
    else
      APXS="$withval"
    fi
])

if test "$APXS" = "no"; then

    # --without-apxs means you want the modules,
    #       but want to tell us how to build them
    AC_MSG_RESULT(yes, but use environment, not apxs)
    echo
    echo "Did you set one or more of these?"
    echo
    echo "APXS_CFLAGS APXS_PREFIX APXS_INCLUDE APXS_LIBEXEC APXS_SYSCONFDIR"
    echo

    AC_MSG_NOTICE([APXS_CFLAGS is $APXS_CFLAGS])

    # try and find the Apache root
    if test -z "$APXS_PREFIX"; then
        if test -d "/usr/local/apache"; then
            APXS_PREFIX="/usr/local/apache"
        else
            AC_MSG_ERROR([You MUST set APXS_PREFIX so the right Apache can be located!])
        fi
    elif test ! -d "$APXS_PREFIX"; then
        AC_MSG_ERROR([APXS_PREFIX of $APXS_PREFIX cannot be found])
    fi
    AC_MSG_NOTICE([APXS_PREFIX is $APXS_PREFIX])
    

    # other subfolders might be derived from APXS_PREFIX
    if test -z "$APXS_INCLUDE"; then
        if test -f "$APXS_PREFIX/include/httpd.h"; then
            APXS_INCLUDE="$APXS_PREFIX/include"
        else
            AC_MSG_ERROR([can't find Apache include files beneath $APXS_PREFIX])
        fi
    elif ! test -f "$APXS_INCLUDE/httpd.h"; then
        AC_MSG_ERROR([APXS_INCLUDE of $APXS_INCLUDE does not contain Apache headers])
    fi
    AC_MSG_NOTICE([APXS_INCLUDE is $APXS_INCLUDE])

    if test -z "$APXS_LIBEXEC"; then
        if test -d "$APXS_PREFIX/libexec"; then
            APXS_LIBEXEC="$APXS_PREFIX/libexec"
        elif test -d "$APXS_PREFIX/modules"; then
            APXS_LIBEXEC="$APXS_PREFIX/modules"
        else
            AC_MSG_ERROR([can't find Apache libexec/module directory beneath $APXS_PREFIX])
        fi
    elif ! test -d "$APXS_LIBEXEC"; then
        AC_MSG_ERROR([APXS_LIBEXEC of $APXS_LIBEXEC does not exist])
    fi
    AC_MSG_NOTICE([APXS_LIBEXEC is $APXS_LIBEXEC])

    if test -z "$APXS_SYSCONFDIR"; then
        if test -d "$APXS_PREFIX/conf"; then
            APXS_SYSCONFDIR="$APXS_PREFIX/conf"
        else
            AC_MSG_ERROR([can't find Apache conf directory beneath $APXS_PREFIX])
        fi
    elif ! test -d "$APXS_SYSCONFDIR"; then
        AC_MSG_ERROR([APXS_SYSCONFDIR of $APXS_SYSCONFDIR does not exist])
    fi
    AC_MSG_NOTICE([APXS_SYSCONFDIR is $APXS_SYSCONFDIR])

    WANT_APACHE="yes"

elif test -n "$APXS"; then

    # extract settings we need from APXS -q
    APXS_CC="`$APXS -q CC`"
    APXS_CFLAGS="`$APXS -q CFLAGS` `$APXS -q CFLAGS_SHLIB`"
    APXS_INCLUDE="`$APXS -q INCLUDEDIR`"
    APXS_LIBEXEC="`$APXS -q LIBEXECDIR`"
    APXS_SYSCONFDIR="`$APXS -q SYSCONFDIR`"

    AC_SUBST(APXS)
    AC_MSG_RESULT(found at $APXS)

    if test -z "`$APXS -q LD_SHLIB`" || test "$APXS_LIBEXEC" = "modules"; then
	    AC_MSG_ERROR(
[Your APXS installation is broken and cannot be used.
    Please see http://www.webdav.org/mod_dav/install.html#apxs for
    more information.])
    fi

    WANT_APACHE="yes"

else
    # guess we're not doing Apache 1.3
    AC_MSG_RESULT(no)
    WANT_APACHE="no"
fi

AM_CONDITIONAL(HAVE_APXS,test -n "$APXS")

if test "$WANT_APACHE" = "yes"; then
    AC_ARG_WITH(apreq,
                AC_HELP_STRING([--with-apreq=PATH], [where libapreq is installed]),
                [if test x_$with_apreq != x_/usr; then
                    LDFLAGS="-L${with_apreq}/lib $LDFLAGS"
                    CPPFLAGS="-I${with_apreq}/include $CPPFLAGS"
                fi])

    saved_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="-I$APXS_INCLUDE $APXS_CFLAGS $CPPFLAGS"
    AC_CHECK_HEADER([libapreq/apache_request.h],,
                AC_MSG_ERROR([unable to find apreq header files]))

dnl    saved_LIBS="$LIBS"
dnl    LIBS="-lapreq $LIBS"
dnl    AC_TRY_LINK(
dnl        [#include <libapreq/apache_request.h>],
dnl        [ApacheRequest_expires],
dnl        [AC_DEFINE(HAVE_APREQ,1,[Define if apreq library was found])],
dnl        [AC_MSG_ERROR([unable to link with apreq])
dnl        ])
dnl    LIBS="$saved_LIBS"
    CPPFLAGS="$saved_CPPFLAGS"

    AC_ARG_ENABLE([apxs-install],
	AC_HELP_STRING([--enable-apxs-install],
			[use apxs to install the apache modules]),
	APXS_INSTALL="yes", )


    AC_SUBST(APXS_CFLAGS)
    AC_SUBST(APXS_INCLUDE)
    AC_SUBST(APXS_LIBEXEC)
    AC_SUBST(APXS_SYSCONFDIR)

    # output the Apache 1.3 makefiles
    WANT_SUBDIRS="$WANT_SUBDIRS mod_shire mod_shibrm"
    AC_CONFIG_FILES([mod_shire/Makefile mod_shibrm/Makefile])
fi

AM_CONDITIONAL(DO_APXS_INSTALL,test -n "$APXS_INSTALL")

AC_SUBST(WANT_SUBDIRS)

if test -n "$APXS_CC" && test "$APXS_CC" != "$CC" ; then
  echo "=================================================================="
  echo "WARNING: You have chosen to compile Apache modules with a different"
  echo "         compiler than the one used to compile Apache."
  echo ""
  echo "    Current compiler:      $CC"
  echo "   Apache's compiler:      $APXS_CC"
  echo ""
  echo "This could cause some problems."
  echo "=================================================================="
fi

AC_OUTPUT


AC_PREREQ([2.50])
AC_INIT([shibboleth], [1.0.1], [mace-shib-users@internet2.edu], [shibboleth])
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE(shibboleth, 1.0.1)

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
AC_CHECK_FUNCS([strchr strdup strstr gmtime_r strtok_r strcasecmp])
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

# Determine whether to use TCP for the shar socket
AC_ARG_ENABLE([tcp],
    AC_HELP_STRING([--enable-tcp], [enable the SHAR to use a TCP socket on Unix]),
    [tcp_enabled=$enableval], [tcp_enabled=default])

if test "x$tcp_enabled" = "x" ; then
   tcp_enabled=yes
fi

if test "$tcp_enabled" = "yes" ; then
    CFLAGS="$CFLAGS -DWANT_TCP_SHAR"
    CXXFLAGS="$CXXFLAGS -DWANT_TCP_SHAR"
fi

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
            [if test x_$with_xmlsec != x_/usr; then
                LDFLAGS="-L${with_xmlsec}/lib $LDFLAGS"
                CPPFLAGS="-I${with_xmlsec}/include $CPPFLAGS"
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
        [xercesc::XMLPlatformUtils::Initialize()],
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

AC_CHECK_HEADER([xsec/utils/XSECPlatformUtils.hpp],,
                AC_MSG_ERROR([unable to find xsec header files]))
saved_LIBS="$LIBS"
LIBS="-lxml-security-c $LIBS"
AC_TRY_LINK(
        [#include <xsec/utils/XSECPlatformUtils.hpp>],
        [XSECPlatformUtils::Initialise()],
        [AC_DEFINE(HAVE_LIBXSEC,1,[Define if XML-Sec library was found])],
        [AC_MSG_ERROR([unable to link with XML-Sec])
                LIBS="$saved_LIBS"
        ])

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
WANT_SUBDIRS="doc shib schemas configs shib-target shar siterefresh test"
AC_CONFIG_FILES([Makefile doc/Makefile shib/Makefile schemas/Makefile \
		 configs/Makefile oncrpc/Makefile oncrpc/rpc/Makefile \
		 shib-target/Makefile shar/Makefile siterefresh/Makefile \
		 test/Makefile])

# now deal with the rpc library, to see if we need to build our own
if test $rpctest = "no"; then
    WANT_SUBDIRS="oncrpc $WANT_SUBDIRS"
	AC_DEFINE(USE_OUR_ONCRPC,1,[Define if using embedded version of ONC RPC.])
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

AC_ARG_ENABLE(apache-13,
	AC_HELP_STRING([--disable-apache-13], [disable the Apache 1.3 modules]))
if test "x$enable_apache_13" = "x" ; then
   enable_apache_13=yes
fi

if test "$enable_apache_13" != yes ; then
   AC_MSG_WARN(Building without Apache...)
   WANT_APACHE=no
else

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
    AC_TRY_COMPILE([#include <libapreq/apache_request.h>],
                   [int i=0],
                   test_apreq="yes",test_apreq="no")
    if test "$test_apreq" = "no"; then
        CPPFLAGS="$CPPFLAGS -U_XOPEN_SOURCE"
        APXS_CFLAGS="$APXS_CFLAGS -U_XOPEN_SOURCE"
        AC_CHECK_HEADER([libapreq/apache_request.h],,
            AC_MSG_ERROR([unable to find a usable libapreq header]))
    fi

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
fi
# always output the Makefile, even if we don't use it
AC_CONFIG_FILES([mod_shire/Makefile mod_shibrm/Makefile])

AM_CONDITIONAL(DO_APXS_INSTALL,test -n "$APXS_INSTALL")

#
# Implement the checks of the MySQL Credential Cache
#
# 1) Assume the user wants MySQL; if it's not found then just continue without
# 2) If the user specifically requested Mysql, look for it and ERROR if not found
# 3) If the user specifically requested no-mysql, don't build it.
#

AC_CONFIG_FILES([shib-mysql-ccache/Makefile])

# determine whether we should enable the mysql ccache
AC_ARG_ENABLE([mysql],
	AC_HELP_STRING([--disable-mysql], [disable the MySQL Credential Cache]),
	[mysql_enabled=$enableval], [mysql_enabled=default])

if test "x$mysql_enabled" = "x" ; then
   mysql_enabled=yes
fi

# Are we trying to build MySQL?
AC_MSG_CHECKING(whether to build the MySQL ccache)
if test "$mysql_enabled" = "yes" ; then
   build_mysql=yes
   AC_MSG_RESULT(yes)
elif test "$mysql_enabled" = "default" ; then
   build_mysql=yes
   AC_MSG_RESULT([yes, if it can be found])
else
   build_mysql=no
   AC_MSG_RESULT(no)
fi

# If we're trying to build MySQL, try to find the mysql_config program,
# verify we've got mysql >= 4, and make sure we can build with mysqld
if test "$build_mysql" = "yes" ; then
   mysql_dir=""
   AC_ARG_WITH(mysql,
	AC_HELP_STRING([--with-mysql=PATH], [directory where mysql is installed]),
	    [if test "$with_mysql" = no ; then
               AC_MSG_ERROR([Try running --disable-mysql instead.])
             elif test "$with_mysql" != yes ; then
               mysql_dir="$with_mysql/bin"
             fi ])

   # Try to find the mysql_config program
   AC_PATH_PROG(MYSQL_CONFIG, mysql_config, no, $mysql_dir $PATH )

   if test "$MYSQL_CONFIG" = no ; then
      if test "$mysql_enabled" = "yes" ; then
        AC_MSG_ERROR(Cannot find mysql_config)
      else
        AC_MSG_WARN(MySQL not found.  skipping.)
      fi
   fi
fi

# if we found mysql_config then build_mysql is 'yes'
if test "$MYSQL_CONFIG" != no ; then
   AC_MSG_CHECKING(for mysql version >= 4)
   mysql_version=`$MYSQL_CONFIG --version`
   mysql_major_version=`echo $mysql_version | awk -F. '{print $1}'`
   mysql_version_ok=yes
   if test $mysql_major_version -lt 4 ; then
     mysql_version_ok=no
     if test "$mysql_enabled" = "yes" ; then
       AC_MSG_ERROR(You need MySQL version >= 4, found $mysql_version)
     fi
     AC_MSG_RESULT(no.. skipping MySQL)
   else
     AC_MSG_RESULT(yes)
   fi
fi

# if mysql_version_ok is 'yes', then we've made it this far.. ;)
if test "$mysql_version_ok" = "yes" ; then
   AC_MSG_CHECKING(for embedded-MySQL libraries)
   MYSQL_LIBS=`$MYSQL_CONFIG --libmysqld-libs`
   if test $? != 0 ; then
      found_mysql=no
      if test "$mysql_enabled" = "yes" ; then
        AC_MSG_ERROR(Could not find the MySQL Embedded-server libraries.)
      else
        AC_MSG_RESULT(no.. skipping MySQL)
      fi
   else
      found_mysql=yes
      AC_MSG_RESULT(yes)
   fi
fi

# if found_mysql=yes then test that we can actually build mysql
if test "$found_mysql" = yes ; then
   MYSQL_CFLAGS=`$MYSQL_CONFIG --cflags`
   MYSQL_CFLAGS=`eval echo $MYSQL_CFLAGS`
   MYSQL_LIBS=`eval echo $MYSQL_LIBS`

   save_CPPFLAGS="$CPPFLAGS"
   CPPFLAGS="$CPPFLAGS $MYSQL_CFLAGS"

   AC_CHECK_HEADER([mysql.h], [have_mysql_h=yes], [have_mysql_h=no])
   if test "$have_mysql_h" = no -a "$mysql_enabled" = "yes" ; then
     AC_MSG_ERROR(unable to find MySQL header files)
   fi

   if test "$have_mysql_h" = yes ; then
      save_LIBS="$LIBS"
      LIBS="$LIBS $MYSQL_LIBS"
      AC_MSG_CHECKING(if we can link againt mysql)
      AC_TRY_LINK(
        [#include <mysql.h>],
        [mysql_server_init(0, NULL, NULL)],
	[have_mysql_libs=yes],
	[have_mysql_libs=no])
      LIBS="$save_LIBS"

      if test "$have_mysql_libs" = no ; then
         if "$mysql_enabled" = "yes" ; then
            AC_MSG_ERROR([unable to link with MySQL Embedded Server Library])
	 else
	    AC_MSG_RESULT(no.  skipping MySQL)
	 fi
      fi
   fi

   CPPFLAGS="$save_CPPFLAGS"
fi

# if have_mysql_libs=yes then go ahead with building MySQL
if test "$have_mysql_libs" = yes ; then
   # this AC_MSG_RESULT is from above!
   AC_MSG_RESULT(yes)
   WANT_SUBDIRS="$WANT_SUBDIRS shib-mysql-ccache"
   AC_SUBST(MYSQL_CFLAGS)
   AC_SUBST(MYSQL_LIBS)
fi


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


AC_PREREQ([2.50])
AC_INIT([shibboleth], [1.2], [shibboleth-users@internet2.edu], [shibboleth])
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE(shibboleth, 1.2)

sinclude(acx_pthread.m4)
sinclude(acx_rpctest.m4)

AC_ARG_ENABLE(debug,
    AC_HELP_STRING(--enable-debug, [Have GCC compile with symbols (Default = no)
]),
    enable_debug=$enableval, enable_debug=no)

if test "$enable_debug" = "yes" ; then
    GCC_CFLAGS="$CFLAGS -g -D_DEBUG"
    GCC_CXXFLAGS="$CXXFLAGS -g -D_DEBUG"
else
    GCC_CFLAGS="$CFLAGS -O2 -DNDEBUG"
    GCC_CXXFLAGS="$CXXFLAGS -O2 -DNDEBUG"
fi

AC_PROG_CC([gcc3 gcc cc])
AC_PROG_CXX([g++3 g++ c++ CC])

if test "$GCC" = "yes" ; then
    CFLAGS="$GCC_CFLAGS"
    CXXFLAGS="$GCC_CXXFLAGS"
fi

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_LANG(C++)

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_STRFTIME
AC_FUNC_STRERROR_R
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

AC_ARG_WITH(dmalloc,
            AC_HELP_STRING([--with-dmalloc=PATH], [where dmalloc is installed]),
            [if test x_$with_dmalloc != x_/usr; then
                LDFLAGS="-L${with_dmalloc}/lib $LDFLAGS"
                CPPFLAGS="-I${with_dmalloc}/include $CPPFLAGS"
            fi
	    AC_CHECK_LIB(dmallocxx, dmalloc_shutdown,,
		         AC_MSG_ERROR([unable to find dmallocxx library]))
	    ])

# OpenSSL settings
AC_PATH_PROG(PKG_CONFIG, pkg-config)
if test "x$PKG_CONFIG" = x || test "x$PKG_CONFIG" = "xno" ; then
    AC_ARG_WITH(openssl, 
            AC_HELP_STRING([--with-openssl=PATH], [where openssl is installed]),
            [if test x_$with_openssl != x_/usr; then
	    SSLLIBS="-L${with_openssl}/lib"
	    SSLFLAGS="-I${with_openssl}/include"
            fi])
    SSLLIBS="$SSLLIBS -lssl -lcrypto"
else
    SSLLIBS="`$PKG_CONFIG --libs openssl`"
    SSLFLAGS="`$PKG_CONFIG --cflags openssl`"
fi
AC_MSG_CHECKING(for OpenSSL libraries)
AC_MSG_RESULT($SSLLIBS)
LIBS="$LIBS $SSLLIBS"
AC_MSG_CHECKING(for OpenSSL cflags)
AC_MSG_RESULT($SSLFLAGS)
CPPFLAGS="$SSLFLAGS $CPPFLAGS"

AC_CHECK_HEADER([openssl/ssl.h],,
                AC_MSG_ERROR([unable to find openssl header files]))
AC_MSG_CHECKING(for ERR_load_CRYPTO_string)
AC_TRY_LINK_FUNC([ERR_load_CRYPTO_strings],,
             AC_MSG_ERROR([unable to link with openssl libraries]))
AC_MSG_RESULT(yes)
AC_MSG_CHECKING(for SSL_library_init)
AC_TRY_LINK_FUNC([SSL_library_init],, 
             AC_MSG_ERROR([unable to link with openssl libraries]))
AC_MSG_RESULT(yes)

# log4cpp settings
AC_PATH_PROG(LOG4CPP_CONFIG,log4cpp-config)
AC_ARG_WITH(log4cpp,
            AC_HELP_STRING([--with-log4cpp=PATH], [where log4cpp is installed]),
            [LOG4CPP_CONFIG="${with_log4cpp}/bin/log4cpp-config"])
if test -f "${LOG4CPP_CONFIG}"; then
    LDFLAGS="`${LOG4CPP_CONFIG} --libs` $LDFLAGS"
    CPPFLAGS="`${LOG4CPP_CONFIG} --cflags` $CPPFLAGS"
else
    AC_MSG_WARN([log4cpp-config not found, guessing at log4cpp build settings])
    LIBS="-llog4cpp $LIBS"
fi
AC_CHECK_HEADER([log4cpp/Category.hh],,AC_MSG_ERROR([unable to find log4cpp header files]))
AC_TRY_LINK(
	[#include <log4cpp/Category.hh>],
	[log4cpp::Category::getInstance("foo")],
	[AC_DEFINE(HAVE_LIBLOG4CPP,1,[Define if log4cpp library was found])],
	[AC_MSG_ERROR([unable to link with log4cpp])])

# Xerces settings
AC_ARG_WITH(xerces, 
            AC_HELP_STRING([--with-xerces=PATH], [where xerces-c is installed]),
            [if test x_$with_xerces != x_/usr; then
                LDFLAGS="-L${with_xerces}/lib $LDFLAGS"
                CPPFLAGS="-I${with_xerces}/include $CPPFLAGS"
            fi])
LIBS="-lxerces-c $LIBS"
AC_CHECK_HEADER([xercesc/dom/DOM.hpp],,
                AC_MSG_ERROR([unable to find xerces header files]))
AC_TRY_LINK(
	[#include <xercesc/util/PlatformUtils.hpp>
#include <xercesc/util/XercesVersion.hpp>],
        [#if _XERCES_VERSION >= 20300
xercesc::XMLPlatformUtils::Initialize();
#else
#error Need Xerces-C version 2.3 or higher
#endif],
	[AC_DEFINE(HAVE_LIBXERCESC,1,[Define if Xerces-C library was found])],
	[AC_MSG_ERROR([unable to link with Xerces])])

# XML-Security settings
AC_ARG_WITH(xmlsec,
            AC_HELP_STRING([--with-xmlsec=PATH], [where xmlsec is installed]),
            [if test x_$with_xmlsec != x_/usr; then
                LDFLAGS="-L${with_xmlsec}/lib $LDFLAGS"
                CPPFLAGS="-I${with_xmlsec}/include $CPPFLAGS"
            fi])
LIBS="-lxml-security-c $LIBS"
AC_CHECK_HEADER([xsec/utils/XSECPlatformUtils.hpp],,AC_MSG_ERROR([unable to find xsec header files]))
AC_TRY_LINK(
        [#include <xsec/utils/XSECPlatformUtils.hpp>],
        [XSECPlatformUtils::Initialise()],
        [AC_DEFINE(HAVE_LIBXSEC,1,[Define if XML-Sec library was found])],
        [AC_MSG_ERROR([unable to link with XML-Sec])])

# OpenSAML settings
AC_ARG_WITH(saml,
            AC_HELP_STRING([--with-saml=PATH], [where saml is installed]),
            [if test x_$with_saml != x_/usr; then
                LDFLAGS="-L${with_saml}/lib $LDFLAGS"
                CPPFLAGS="-I${with_saml}/include $CPPFLAGS"
            fi])
AC_CHECK_HEADER([saml/saml.h],,
                AC_MSG_ERROR([unable to find saml header files]))
LIBS="-lsaml $LIBS"
AC_TRY_LINK(
	[#include <saml/saml.h>
#include <saml/version.h>],
	[#if _OPENSAML_VERSION >= 10000
saml::SAMLConfig::getConfig();
#else
#error Need OpenSAML version 1.0 or higher
#endif],
        [AC_DEFINE(HAVE_SAML,1,[Define if saml library was found])],
        [AC_MSG_ERROR([unable to link with saml, or version too old])])

# output the underlying makefiles
WANT_SUBDIRS="doc shib schemas configs shib-target shar siterefresh test xmlproviders"
AC_CONFIG_FILES([Makefile doc/Makefile shib/Makefile schemas/Makefile \
		 configs/Makefile oncrpc/Makefile oncrpc/rpc/Makefile \
		 shib-target/Makefile shar/Makefile siterefresh/Makefile \
		 test/Makefile xmlproviders/Makefile])


# now deal with the rpc library, to see if we need to build our own
if test $rpctest = "no"; then
    WANT_SUBDIRS="oncrpc $WANT_SUBDIRS"
	AC_DEFINE(USE_OUR_ONCRPC,1,[Define if using embedded version of ONC RPC.])
fi
AM_CONDITIONAL(USE_OUR_ONCRPC,test "$rpctest" = "no")


# Apache 1.3 (mod_shib_13)
#   --enable-apache-13
#   --with-apxs      (DSO build, the normal way, uses apxs to derive build flags)
#   --without-apxs   (DSO build, you tell us how to build using the environment)

AC_ARG_ENABLE(apache-13,
	AC_HELP_STRING([--enable-apache-13], [enable the Apache 1.3 modules]),
	[ if test "x$enableval" = "x" ; then
              WANT_APACHE_13=yes
	  else
	      WANT_APACHE_13="$enableval"
	  fi
	], [ WANT_APACHE_13=no ])
AC_MSG_CHECKING(whether to build Apache-1.3 support)
if test "$WANT_APACHE_13" != yes && test "$WANT_APACHE_13" != no ; then
   WANT_APACHE_13=yes
fi
AC_MSG_RESULT($WANT_APACHE_13)

if test "$WANT_APACHE_13" = yes ; then

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
],
[
    AC_PATH_PROG(APXS, apxs, no)
])

AC_MSG_CHECKING([for dynamic Apache-1.3 module support (w/ or w/o APXS)])
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

    WANT_APACHE_13="yes"

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

    WANT_APACHE_13="yes"

else
    # guess we're not doing Apache 1.3
    AC_MSG_RESULT(no)
    WANT_APACHE_13="no"
fi
fi

AC_SUBST(APXS_CFLAGS)
AC_SUBST(APXS_INCLUDE)
AC_SUBST(APXS_LIBEXEC)
AC_SUBST(APXS_SYSCONFDIR)
AM_CONDITIONAL(HAVE_APXS,test -n "$APXS")


# Apache 2.0 (mod_shib_20)
#   --enable-apache-20
#   --with-apxs2       (DSO build, the normal way, uses apxs to derive build flags)
#	--with-apr         (DSO build, APR development package installed separately)
#   --without-apxs2    (DSO build, you tell us how to build using the environment)

AC_ARG_ENABLE(apache-20,
	AC_HELP_STRING([--enable-apache-20], [enable the Apache 2.0 modules]),
	[ if test "x$enableval" = "x" ; then
              WANT_APACHE_20=yes
	  else
	      WANT_APACHE_20="$enableval"
	  fi
	], [ WANT_APACHE_20=no ])

AC_MSG_CHECKING(whether to build Apache-2.0 support)
if test "$WANT_APACHE_20" != yes && test "$WANT_APACHE_20" != no ; then
   WANT_APACHE_20=yes
fi
AC_MSG_RESULT($WANT_APACHE_20)

if test "$WANT_APACHE_20" = yes ; then

AC_ARG_WITH(apxs2,
[  --with-apxs2[=FILE]        Build shared Apache module(s). FILE is the optional
                          pathname to the Apache apxs tool; defaults to "apxs".],
[
    if test "$withval" = "yes"; then
      for i in /usr/sbin /usr/local/apache2/bin /usr/local/apache/bin ; do
        if test -f "$i/apxs"; then
          APXS2="$i/apxs"
        fi
      done
      if test -z "$APXS2"; then
        APXS2=apxs
      fi
    else
      APXS2="$withval"
    fi
],
[
    AC_PATH_PROG(APXS2, apxs, no)
])

AC_MSG_CHECKING([for dynamic Apache-2 module support (w/ or w/o APXS)])
if test "$APXS2" = "no"; then

    # --without-apxs2 means you want the modules,
    #       but want to tell us how to build them
    AC_MSG_RESULT(yes, but use environment, not apxs)
    echo
    echo "Did you set one or more of these?"
    echo
    echo "APXS2_CFLAGS APXS2_PREFIX APXS2_INCLUDE APXS2_LIBEXEC APXS2_SYSCONFDIR"
    echo

    AC_MSG_NOTICE([APXS2_CFLAGS is $APXS2_CFLAGS])

    # try and find the Apache root
    if test -z "$APXS2_PREFIX"; then
        if test -d "/usr/local/apache"; then
            APXS2_PREFIX="/usr/local/apache"
        else
            AC_MSG_ERROR([You MUST set APXS2_PREFIX so the right Apache-2 can be located!])
        fi
    elif test ! -d "$APXS2_PREFIX"; then
        AC_MSG_ERROR([APXS2_PREFIX of $APXS2_PREFIX cannot be found])
    fi
    AC_MSG_NOTICE([APXS2_PREFIX is $APXS2_PREFIX])
    

    # other subfolders might be derived from APXS2_PREFIX
    if test -z "$APXS2_INCLUDE"; then
        if test -f "$APXS2_PREFIX/include/httpd.h"; then
            APXS2_INCLUDE="$APXS2_PREFIX/include"
        else
            AC_MSG_ERROR([can't find Apache-2 include files beneath $APXS2_PREFIX])
        fi
    elif ! test -f "$APXS2_INCLUDE/httpd.h"; then
        AC_MSG_ERROR([APXS2_INCLUDE of $APXS2_INCLUDE does not contain Apache-2 headers])
    fi
    AC_MSG_NOTICE([APXS2_INCLUDE is $APXS2_INCLUDE])

    if test -z "$APXS2_LIBEXEC"; then
        if test -d "$APXS2_PREFIX/libexec"; then
            APXS2_LIBEXEC="$APXS2_PREFIX/libexec"
        elif test -d "$APXS2_PREFIX/modules"; then
            APXS2_LIBEXEC="$APXS2_PREFIX/modules"
        else
            AC_MSG_ERROR([can't find Apache-2 libexec/module directory beneath $APXS2_PREFIX])
        fi
    elif ! test -d "$APXS2_LIBEXEC"; then
        AC_MSG_ERROR([APXS2_LIBEXEC of $APXS2_LIBEXEC does not exist])
    fi
    AC_MSG_NOTICE([APXS2_LIBEXEC is $APXS2_LIBEXEC])

    if test -z "$APXS2_SYSCONFDIR"; then
        if test -d "$APXS2_PREFIX/conf"; then
            APXS2_SYSCONFDIR="$APXS2_PREFIX/conf"
        else
            AC_MSG_ERROR([can't find Apache-2 conf directory beneath $APXS2_PREFIX])
        fi
    elif ! test -d "$APXS2_SYSCONFDIR"; then
        AC_MSG_ERROR([APXS2_SYSCONFDIR of $APXS2_SYSCONFDIR does not exist])
    fi
    AC_MSG_NOTICE([APXS2_SYSCONFDIR is $APXS2_SYSCONFDIR])

    WANT_APACHE_20="yes"

elif test -n "$APXS2"; then

	# APR settings
	AC_PATH_PROG(APR_CONFIG,apr-config)
	AC_ARG_WITH(apr,
	            AC_HELP_STRING([--with-apr=PATH], [where APR is installed]),
	            [APR_CONFIG="${with_apr}/bin/apr-config"])
	if test -f "${APR_CONFIG}"; then
	    APR_CFLAGS="`${APR_CONFIG} --cflags` `${APR_CONFIG} --cppflags` `${APR_CONFIG} --includes`"
	fi

    # extract settings we need from APXS2 -q
    APXS2_CC="`$APXS2 -q CC`"
    APXS2_CFLAGS="`$APXS2 -q CFLAGS` `$APXS2 -q CFLAGS_SHLIB` $APR_CFLAGS"
    APXS2_INCLUDE="`$APXS2 -q INCLUDEDIR`"
    APXS2_LIBEXEC="`$APXS2 -q LIBEXECDIR`"
    APXS2_SYSCONFDIR="`$APXS2 -q SYSCONFDIR`"

    AC_SUBST(APXS2)
    AC_MSG_RESULT(found at $APXS2)

    if test -z "`$APXS2 -q LD_SHLIB`" && test -z "`$APXS2 -q LIBEXECDIR`" \
       || test "$APXS2_LIBEXEC" = "modules"; then
	    AC_MSG_ERROR(
[Your APXS installation is broken and cannot be used.
    Please see http://www.webdav.org/mod_dav/install.html#apxs for
    more information.])
    fi

    WANT_APACHE_20="yes"

else
    # guess we're not doing Apache 2.0
    AC_MSG_RESULT(no)
    WANT_APACHE_20="no"
fi
fi

AC_SUBST(APXS2_CFLAGS)
AC_SUBST(APXS2_INCLUDE)
AC_SUBST(APXS2_LIBEXEC)
AC_SUBST(APXS2_SYSCONFDIR)
AM_CONDITIONAL(HAVE_APXS2,test -n "$APXS2")

# always output the Makefile, even if you don't use it
AC_CONFIG_FILES([apache/Makefile])
AM_CONDITIONAL(BUILD_AP13,test "$WANT_APACHE_13" = "yes")
AM_CONDITIONAL(BUILD_AP20,test "$WANT_APACHE_20" = "yes")

# add the apache module to the list of wanted subdirs..
if test "$WANT_APACHE_13" = "yes" || test "$WANT_APACHE_20" = "yes" ; then
    WANT_SUBDIRS="$WANT_SUBDIRS apache"
fi


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
        [#include <mysql.h>
	 #include <stdio.h>],
        [mysql_server_init(0, NULL, NULL)],
	[have_mysql_libs=yes],
	[have_mysql_libs=no])
      LIBS="$save_LIBS"

      if test "$have_mysql_libs" = no ; then
         if test "$mysql_enabled" = "yes" ; then
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
  echo "WARNING: You have chosen to compile Apache-1.3 modules with a different"
  echo "         compiler than the one used to compile Apache."
  echo ""
  echo "    Current compiler:      $CC"
  echo "   Apache's compiler:      $APXS_CC"
  echo ""
  echo "This could cause some problems."
  echo "=================================================================="
fi

if test -n "$APXS2_CC" && test "$APXS2_CC" != "$CC" ; then
  echo "=================================================================="
  echo "WARNING: You have chosen to compile Apache-2 modules with a different"
  echo "         compiler than the one used to compile Apache."
  echo ""
  echo "    Current compiler:      $CC"
  echo "   Apache's compiler:      $APXS2_CC"
  echo ""
  echo "This could cause some problems."
  echo "=================================================================="
fi

AC_OUTPUT


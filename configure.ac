AC_PREREQ([2.50])
AC_INIT([shibboleth], [2.0], [shibboleth-users@internet2.edu], [shibboleth])
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE([shibboleth],[2.0])

sinclude(acx_pthread.m4)

AC_ARG_ENABLE(debug,
    AC_HELP_STRING(--enable-debug, [Have GCC compile with symbols (Default = no)
]),
    enable_debug=$enableval, enable_debug=no)

if test "$enable_debug" = "yes" ; then
    GCC_CFLAGS="$CFLAGS -Wall -g -D_DEBUG"
    GCC_CXXFLAGS="$CXXFLAGS -Wall -g -D_DEBUG"
else
    GCC_CFLAGS="$CFLAGS -Wall -O2 -DNDEBUG"
    GCC_CXXFLAGS="$CXXFLAGS -Wall -O2 -DNDEBUG"
fi

AC_PROG_CC([gcc gcc3 cc])
AC_PROG_CXX([g++ g++3 c++ CC])

if test "$GCC" = "yes" ; then
    CFLAGS="$GCC_CFLAGS"
    CXXFLAGS="$GCC_CXXFLAGS"
fi

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_LANG(C++)

# C++ requirements
AC_CXX_REQUIRE_STL
AC_CXX_NAMESPACES

AC_LANG(C)

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_STRFTIME
AC_FUNC_STRERROR_R
AC_CHECK_FUNCS([strchr strdup strstr gmtime_r ctime_r strtok_r strcasecmp])
AC_CHECK_HEADERS([dlfcn.h])

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

AC_LANG(C++)

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
AC_MSG_CHECKING([Xerces version])
AC_PREPROC_IFELSE(
        [AC_LANG_PROGRAM([#include <xercesc/util/XercesVersion.hpp>],
[#if  _XERCES_VERSION > 20200 && _XERCES_VERSION != 20600
int i = 0;
#else
#error requires version > 2.2.0 but not 2.6.0
#endif])],
        [AC_MSG_RESULT(OK)],
        [AC_MSG_ERROR([Shibboleth requires patched Xerces version 2.6.1 (http://shibboleth.internet2.edu/downloads/)])])
AC_TRY_LINK(
        [#include <xercesc/util/PlatformUtils.hpp>],
        [xercesc::XMLPlatformUtils::Initialize()],
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
AC_CHECK_HEADER([xsec/xenc/XENCEncryptionMethod.hpp],,AC_MSG_ERROR([unable to find xml-security 1.1 header files]),[#include <xercesc/dom/DOM.hpp>])
AC_TRY_LINK(
        [#include <xsec/utils/XSECPlatformUtils.hpp>],
        [XSECPlatformUtils::Initialise()],
        [AC_DEFINE(HAVE_LIBXSEC,1,[Define if XML-Sec library was found])],
        [AC_MSG_ERROR([unable to link with xml-security])])

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
	[#if _OPENSAML_VERSION >= 10100
saml::SAMLConfig::getConfig();
#else
#error Need OpenSAML version 1.1 or higher
#endif],
        [AC_DEFINE(HAVE_SAML,1,[Define if saml library was found])],
        [AC_MSG_ERROR([unable to link with saml, or version too old])])

# output the underlying makefiles
WANT_SUBDIRS="doc shib schemas configs shib-target shar siterefresh test xmlproviders"
AC_CONFIG_FILES([Makefile doc/Makefile shib/Makefile schemas/Makefile \
		 configs/Makefile shib-target/Makefile shar/Makefile siterefresh/Makefile \
		 test/Makefile selinux/Makefile])


#
# Build NSAPI module?
#
AC_MSG_CHECKING(for NSAPI module option)
AC_ARG_WITH(nsapi,
	AC_HELP_STRING([--with-nsapi=DIR], [Build NSAPI module for Netscape/iPlanet/SunONE]),
	[WANT_NSAPI=$withval],[WANT_NSAPI=no])
AC_MSG_RESULT($WANT_NSAPI)

if test "$WANT_NSAPI" != "no"; then
  if test ! -d $WANT_NSAPI/bin ; then
    AC_MSG_ERROR(Please specify the path to the root of your Netscape/iPlanet/SunONE server using --with-nsapi=DIR)
  fi
  AC_MSG_CHECKING(for NSAPI include files)
  if test -d $WANT_NSAPI/include ; then
    NSAPI_INCLUDE=$WANT_NSAPI/include
    AC_MSG_RESULT(Netscape-Enterprise 3.x style)
    AC_CHECK_HEADERS([$NSAPI_INCLUDE/nsapi.h])
    NSAPI_INCLUDE="$NSAPI_INC_DIR -I$NSAPI_INCLUDE"
  fi
  if test -d $WANT_NSAPI/plugins/include ; then
    test -n "$NSAPI_INCLUDE" && NSAPI_INC_DIR="-I$NSAPI_INCLUDE"
    NSAPI_INCLUDE="$WANT_NSAPI/plugins/include"
    AC_MSG_RESULT(iPlanet 4.x / SunONE 6.x style)
    AC_CHECK_HEADERS([$NSAPI_INCLUDE/nsapi.h])
    NSAPI_INCLUDE="$NSAPI_INC_DIR -I$NSAPI_INCLUDE"
  fi
  if test "$NSAPI_INCLUDE" = ""; then
    AC_MSG_ERROR(Please check you have nsapi.h in either $WANT_NSAPI/include or $WANT_NSAPI/plugins/include)
  fi
fi

AC_SUBST(NSAPI_INCLUDE)

# always output the Makefile, even if you don't use it
AC_CONFIG_FILES([nsapi_shib/Makefile])
AM_CONDITIONAL(BUILD_NSAPI,test ! "$WANT_NSAPI" = "no")

# add the NSAPI module to the list of wanted subdirs..
if test ! "$WANT_NSAPI" = "no" ; then
    WANT_SUBDIRS="$WANT_SUBDIRS nsapi_shib"
fi


# Apache 1.3 (mod_shib_13)
#   --enable-apache-13
#   --with-apxs      (DSO build, the normal way, uses apxs to derive build flags)

AC_ARG_ENABLE(apache-13,
	AC_HELP_STRING([--enable-apache-13], [enable the Apache 1.3 module]),
	[ if test "x$enableval" = "x" ; then
              WANT_APACHE_13=yes
	  else
	      WANT_APACHE_13="$enableval"
	  fi
	],[ WANT_APACHE_13=no ])
AC_MSG_CHECKING(whether to build Apache 1.3 module)
if test "$WANT_APACHE_13" != yes && test "$WANT_APACHE_13" != no ; then
   WANT_APACHE_13=yes
fi
AC_MSG_RESULT($WANT_APACHE_13)

if test "$WANT_APACHE_13" = "yes" ; then
    AC_ARG_WITH(apxs, 
        AC_HELP_STRING([--with-apxs=FILE], [Specifies where to find the Apache 1.3 apxs script.]),
        [
        AC_MSG_CHECKING(for user-specified apxs name/location)
        if test "$withval" != "no" ; then
          if test "$withval" != "yes"; then
            APXS=$withval
            AC_MSG_RESULT("$withval")
          fi
        fi
        ],
        [
        AC_PATH_PROG(APXS, apxs, no)
        if test "$APXS" = "no" ; then
          for i in /usr/sbin /usr/local/apache/bin ; do
            if test "$APXS" = "no" && test -f "$i/apxs"; then
              APXS="$i/apxs"
            fi
          done
        fi
        ])

    AC_MSG_CHECKING([to see if apxs was located])
    if test ! -f "$APXS" ; then
        AC_MSG_RESULT(no)
        AC_MSG_ERROR([Unable to locate apxs script. An Apache development package may be missing from your server, or you may need to use the --with-apxs option.])
    fi
    AC_MSG_RESULT($APXS)
    AC_SUBST(APXS)

    # extract settings we need from APXS -q
    APXS_CC="`$APXS -q CC`"
    APXS_CFLAGS="`$APXS -q CPPFLAGS` `$APXS -q CFLAGS` `$APXS -q CFLAGS_SHLIB`"
    APXS_INCLUDE="`$APXS -q INCLUDEDIR`"
fi

AC_SUBST(APXS_CFLAGS)
AC_SUBST(APXS_INCLUDE)


# Apache 2.0 (mod_shib_20)
#   --enable-apache-20
#   --with-apxs2      (DSO build, the normal way, uses apxs to derive build flags)
#	--with-apr        (DSO build, APR development package installed separately)

AC_ARG_ENABLE(apache-20,
	AC_HELP_STRING([--enable-apache-20], [enable the Apache 2.0 module]),
	[ if test "x$enableval" = "x" ; then
              WANT_APACHE_20=yes
	  else
	      WANT_APACHE_20="$enableval"
	  fi
	],[ WANT_APACHE_20=no ])
AC_MSG_CHECKING(whether to build Apache 2.0 module)
if test "$WANT_APACHE_20" != yes && test "$WANT_APACHE_20" != no ; then
   WANT_APACHE_20=yes
fi
AC_MSG_RESULT($WANT_APACHE_20)

if test "$WANT_APACHE_20" = "yes" ; then
    AC_ARG_WITH(apxs2, 
        AC_HELP_STRING([--with-apxs2=FILE], [Specifies where to find the Apache 2.0 apxs script.]),
        [
        AC_MSG_CHECKING(for user-specified Apache2 apxs name/location)
        if test "$withval" != "no" ; then
          if test "$withval" != "yes"; then
            APXS2=$withval
            AC_MSG_RESULT("$withval")
          fi
        fi
        ],
        [
        AC_PATH_PROG(APXS2, apxs2, no)
        if test "$APXS2" = "no" ; then
            AC_PATH_PROG(APXS2, apxs, no)
        fi
        if test "$APXS2" = "no" ; then
          for i in /usr/sbin /usr/local/apache2/bin /usr/local/apache/bin ; do
            if test "$APXS2" = "no" && test -f "$i/apxs2" ; then
              APXS2="$i/apxs2"
            fi
          done
          if test "$APXS2" = "no" ; then
            for i in /usr/sbin /usr/local/apache2/bin /usr/local/apache/bin ; do
              if test "$APXS2" = "no" && test -f "$i/apxs" ; then
                APXS2="$i/apxs"
              fi
            done
          fi
        fi
        ])

    AC_MSG_CHECKING([to see if Apache2 apxs was located])
    if test ! -f "$APXS2" ; then
        AC_MSG_RESULT(no)
        AC_MSG_ERROR([Unable to locate Apache2 apxs script. An Apache development package may be missing from your server, or you may need to use the --with-apxs2 option.])
    fi
    AC_MSG_RESULT($APXS2)
    AC_SUBST(APXS2)

    # APR settings
    AC_ARG_WITH(apr, 
        AC_HELP_STRING([--with-apr=PATH], [where apr-config is installed]),
        [
        AC_MSG_CHECKING(for user-specified apr-config name/location)
        if test "$withval" != "no" ; then
            if test "$withval" != "yes"; then
                APR_CONFIG=$withval
                AC_MSG_RESULT("$withval")
            fi
        fi
        ],
        [
        AC_PATH_PROG(APR_CONFIG, apr-config)
        ])
	if test -f "${APR_CONFIG}"; then
        APR_CFLAGS="`${APR_CONFIG} --cflags` `${APR_CONFIG} --cppflags` `${APR_CONFIG} --includes`"
    else
        AC_MSG_ERROR([Unable to locate apr-config, may need --with-apr option.])
    fi

    # extract settings we need from APXS2 -q
    APXS2_CC="`$APXS2 -q CC`"
    APXS2_CFLAGS="`$APXS2 -q CPPFLAGS` `$APXS2 -q CFLAGS` `$APXS2 -q CFLAGS_SHLIB` $APR_CFLAGS"
    APXS2_INCLUDE="`$APXS2 -q INCLUDEDIR`"
fi

AC_SUBST(APXS2_CFLAGS)
AC_SUBST(APXS2_INCLUDE)


# Apache 2.2 (mod_shib_22)
#   --enable-apache-22
#   --with-apxs22     (DSO build, the normal way, uses apxs to derive build flags)
#	--with-apr1       (DSO build, APR development package installed separately)

AC_ARG_ENABLE(apache-22,
	AC_HELP_STRING([--enable-apache-22], [enable the Apache 2.2 module]),
	[ if test "x$enableval" = "x" ; then
              WANT_APACHE_22=yes
	  else
	      WANT_APACHE_22="$enableval"
	  fi
	],[ WANT_APACHE_22=no ])
AC_MSG_CHECKING(whether to build Apache 2.2 module)
if test "$WANT_APACHE_22" != yes && test "$WANT_APACHE_22" != no ; then
   WANT_APACHE_22=yes
fi
AC_MSG_RESULT($WANT_APACHE_22)

if test "$WANT_APACHE_22" = "yes" ; then
    AC_ARG_WITH(apxs22, 
        AC_HELP_STRING([--with-apxs22=FILE], [Specifies where to find the Apache 2.2 apxs script.]),
        [
        AC_MSG_CHECKING(for user-specified Apache2.2 apxs name/location)
        if test "$withval" != "no" ; then
          if test "$withval" != "yes"; then
            APXS22=$withval
            AC_MSG_RESULT("$withval")
          fi
        fi
        ],
        [
        AC_PATH_PROG(APXS22, apxs2, no)
        if test "$APXS22" = "no" ; then
            AC_PATH_PROG(APXS22, apxs, no)
        fi
        if test "$APXS22" = "no" ; then
          for i in /usr/sbin /usr/local/apache2/bin /usr/local/apache/bin ; do
            if test "$APXS22" = "no" && test -f "$i/apxs2" ; then
              APXS22="$i/apxs2"
            fi
          done
          if test "$APXS22" = "no" ; then
            for i in /usr/sbin /usr/local/apache2/bin /usr/local/apache/bin ; do
              if test "$APXS22" = "no" && test -f "$i/apxs" ; then
                APXS22="$i/apxs"
              fi
            done
          fi
        fi
        ])

    AC_MSG_CHECKING([to see if Apache2.2 apxs was located])
    if test ! -f "$APXS22" ; then
        AC_MSG_RESULT(no)
        AC_MSG_ERROR([Unable to locate Apache2.2 apxs script. An Apache development package may be missing from your server, or you may need to use the --with-apxs22 option.])
    fi
    AC_MSG_RESULT($APXS22)
    AC_SUBST(APXS22)

    # APR1 settings
    AC_ARG_WITH(apr1, 
        AC_HELP_STRING([--with-apr1=PATH], [where apr-1-config is installed]),
        [
        AC_MSG_CHECKING(for user-specified apr-1-config name/location)
        if test "$withval" != "no" ; then
            if test "$withval" != "yes"; then
                APR1_CONFIG=$withval
                AC_MSG_RESULT("$withval")
            fi
        fi
        ],
        [
        AC_PATH_PROG(APR1_CONFIG, apr-1-config)
        ])
	if test -f "${APR1_CONFIG}"; then
        APR1_CFLAGS="`${APR1_CONFIG} --cflags` `${APR1_CONFIG} --cppflags` `${APR1_CONFIG} --includes`"
    else
        AC_MSG_ERROR([Unable to locate apr-1-config, may need --with-apr1 option.])
    fi

    # extract settings we need from APXS22 -q
    APXS22_CC="`$APXS22 -q CC`"
    APXS22_CFLAGS="`$APXS22 -q CPPFLAGS` `$APXS22 -q CFLAGS` `$APXS22 -q CFLAGS_SHLIB` $APR1_CFLAGS"
    APXS22_INCLUDE="`$APXS22 -q INCLUDEDIR`"
fi

AC_SUBST(APXS22_CFLAGS)
AC_SUBST(APXS22_INCLUDE)

# always output the Makefile, even if you don't use it
AC_CONFIG_FILES([apache/Makefile])
AM_CONDITIONAL(BUILD_AP13,test "$WANT_APACHE_13" = "yes")
AM_CONDITIONAL(BUILD_AP20,test "$WANT_APACHE_20" = "yes")
AM_CONDITIONAL(BUILD_AP22,test "$WANT_APACHE_22" = "yes")

# add the apache module to the list of wanted subdirs..
if test "$WANT_APACHE_13" = "yes" || test "$WANT_APACHE_20" = "yes" || test "$WANT_APACHE_22" = "yes" ; then
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


#
# Implement the checks of the ODBC Credential Cache
#
# 1) Assume the user wants ODBC; if it's not found then just continue without
# 2) If the user specifically requested odbc, look for it and ERROR if not found
# 3) If the user specifically requested no-odbc, don't build it.
#

AC_CONFIG_FILES([odbc_ccache/Makefile])

# determine whether we should enable the odbc ccache
AC_ARG_ENABLE([odbc],
	AC_HELP_STRING([--disable-odbc], [disable the ODBC Credential Cache]),
	[odbc_enabled=$enableval], [odbc_enabled=default])

if test "x$odbc_enabled" = "x" ; then
   odbc_enabled=yes
fi

# Are we trying to build ODBC?
AC_MSG_CHECKING(whether to build the ODBC ccache)
if test "$odbc_enabled" = "yes" ; then
   build_odbc=yes
   AC_MSG_RESULT(yes)
elif test "$odbc_enabled" = "default" ; then
   build_odbc=yes
   AC_MSG_RESULT([yes, if it can be found])
else
   build_odbc=no
   AC_MSG_RESULT(no)
fi

# If we're trying to build ODBC, try to find the odbc_config program.
if test "$build_odbc" = "yes" ; then
   odbc_dir=""
   AC_ARG_WITH(odbc,
	AC_HELP_STRING([--with-odbc=PATH], [directory where odbc is installed]),
	    [if test "$with_odbc" = no ; then
               AC_MSG_ERROR([Try running --disable-odbc instead.])
             elif test "$with_odbc" != yes ; then
               odbc_dir="$with_odbc/bin"
             fi ])

   # Try to find the mysql_config program
   AC_PATH_PROG(ODBC_CONFIG, odbc_config, no, $odbc_dir $PATH )

   if test "$ODBC_CONFIG" = no ; then
      if test "$odbc_enabled" = "yes" ; then
        AC_MSG_ERROR(Cannot find odbc_config)
      else
        AC_MSG_WARN(ODBC not found, skipping.)
      fi
   fi
fi

if test "$build_odbc" = yes ; then
   ODBC_CFLAGS=`$ODBC_CONFIG --cflags`
   ODBC_CFLAGS=`eval echo $ODBC_CFLAGS`
   ODBC_LIBS=`$ODBC_CONFIG --libs`
   ODBC_LIBS=`eval echo $ODBC_LIBS`

   save_CPPFLAGS="$CPPFLAGS"
   CPPFLAGS="$CPPFLAGS $ODBC_CFLAGS"

   AC_CHECK_HEADER([sql.h], [have_sql_h=yes], [have_sql_h=no])
   if test "$have_sql_h" = no -a "$odbc_enabled" = "yes" ; then
     AC_MSG_ERROR(unable to find ODBC header files)
   fi

   if test "$have_sql_h" = yes ; then
      save_LIBS="$LIBS"
      LIBS="$LIBS $ODBC_LIBS"
      AC_MSG_CHECKING(if we can link againt ODBC)
      AC_TRY_LINK(
        [#include <sql.h>
         #include <sqlext.h>
         #include <stdio.h>],
        [SQLSetEnvAttr(SQL_NULL_HANDLE, SQL_ATTR_CONNECTION_POOLING, (void*)SQL_CP_ONE_PER_HENV, 0)],
        [have_odbc_libs=yes],
        [have_odbc_libs=no])
      LIBS="$save_LIBS"

      if test "$have_odbc_libs" = no ; then
         if test "$odbc_enabled" = "yes" ; then
            AC_MSG_ERROR([unable to link with ODBC Library])
         else
            AC_MSG_RESULT(no, skipping ODBC)
         fi
      fi
   fi

   CPPFLAGS="$save_CPPFLAGS"
fi

# if have_odbc_libs=yes then go ahead with building ODBC
if test "$have_odbc_libs" = yes ; then
   # this AC_MSG_RESULT is from above!
   AC_MSG_RESULT(yes)
   WANT_SUBDIRS="$WANT_SUBDIRS odbc_ccache"
   AC_SUBST(ODBC_CFLAGS)
   AC_SUBST(ODBC_LIBS)
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
  echo "This could cause problems."
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
  echo "This could cause problems."
  echo "=================================================================="
fi

LIBTOOL="$LIBTOOL --silent"

AC_OUTPUT


AC_PREREQ([2.69])
AC_INIT([shibboleth-sp],[4.0.0alpha1],[https://shibboleth.atlassian.net/jira],[shibboleth-sp])
AC_CONFIG_SRCDIR(shibsp)
AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIR(m4)
AM_INIT_AUTOMAKE
PKG_INSTALLDIR

AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug],[Produce debug variant (Default = no)]),
    enable_debug=$enableval, enable_debug=no)

if test "$enable_debug" = "yes" ; then
    AM_CFLAGS="-D_DEBUG"
    AM_CXXFLAGS="-D_DEBUG"
fi

AC_CONFIG_HEADERS([config.h shibsp/config_pub.h])
AC_CONFIG_FILES([shibsp.pc])

AC_PROG_CC([gcc gcc3 cc])
AC_PROG_CXX([g++ g++3 c++ CC])

AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_CXXFLAGS])

LT_INIT([disable-static])

AC_LANG(C)

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_STRUCT_TM
AC_HEADER_DIRENT

# Checks for library functions.
AC_FUNC_STRFTIME
AC_CHECK_HEADERS([sys/utsname.h grp.h pwd.h])
AC_CHECK_HEADERS([sys/socket.h], [AC_DEFINE([SHIBSP_HAVE_SYS_SOCKET_H],[1],[Define to 1 if you have the <sys/socket> header file.])], [])
AC_CHECK_FUNCS([strchr strdup strstr timegm gmtime_r localtime_r strtok_r strcasecmp getpwnam getgrnam initgroups])
AC_CHECK_TYPES([struct sockaddr_storage], [], [], [[#include <sys/socket.h>]])
AC_CHECK_MEMBERS([struct sockaddr.sa_len], [], [], [[#include <sys/socket.h>]])
AC_CHECK_HEADERS([dlfcn.h])

# Check for dlopen.
AX_SAVE_FLAGS
LIBS=""
AC_SEARCH_LIBS([dlopen],[dl],,[AC_MSG_ERROR([cannot find dlopen() function])])
AC_SUBST([dlopen_LIBS],[$LIBS])
AX_RESTORE_FLAGS

AX_PTHREAD(,[AC_MSG_ERROR([unable to find pthreads, currently this is required])])

AC_LANG([C++])

# On GNU/Linux, g++ always defines the preprocessor macro _GNU_SOURCE
# because libstdc++ requires it.  This in turn selects the GNU version of
# strerror_r(), which returns char* and may not use the passed buffer
# (see https://gcc.gnu.org/onlinedocs/libstdc++/faq.html#faq.predefined).
AC_FUNC_STRERROR_R

# C++ requirements
AC_CXX_NAMESPACES
AC_CXX_REQUIRE_STL

AX_CXX_COMPILE_STDCXX([11])
AX_CXX_COMPILE_STDCXX([14],,[optional])
AX_CXX_COMPILE_STDCXX([17],,[optional])

# Boost
BOOST_REQUIRE
BOOST_PROPERTYTREE
BOOST_STRING_ALGO
BOOST_TOKENIZER
BOOST_TEST

## Use Boost for regex?
AC_ARG_ENABLE([boost-regex],
    AS_HELP_STRING([--disable-boost-regex],[do not use Boost for regular expression support]),
    [boostregex_enabled=$enableval], [boostregex_enabled=yes])
if test "x$boostregex_enabled" = "x" ; then
    boostregex_enabled=yes
fi
AC_MSG_CHECKING(whether to use Boost for regular expressions)
if test "$boostregex_enabled" = "no" ; then
    AC_MSG_RESULT(no)
else
    AC_MSG_RESULT(yes)
    BOOST_REGEX
    AC_DEFINE([SHIBSP_USE_BOOST_REGEX],[1],[Define if using Boost for regular expressions.])
fi

AX_PKG_CHECK_MODULES([libcurl],,[libcurl >= 7.4.2],
    [AC_DEFINE([HAVE_LIBCURL],[1],[Define to 1 if libcurl library is available.])])

AC_CHECK_DECLS([CURLOPT_ACCEPT_ENCODING],,,[[#include <curl/curl.h>]])

# Thank you Solaris, really.
AC_MSG_CHECKING(for ctime_r)
if test -z "$ac_cv_ctime_args"; then
    AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([[#include <time.h>]], [[time_t clock; char buf[26]; ctime_r(&clock, buf);]])],
        [ac_cv_ctime_args=2],[])

    AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([[#include <time.h>]], [[time_t clock; char buf[26]; ctime_r(&clock, buf, 26);]])],
        [ac_cv_ctime_args=3],[])
fi
if test -z "$ac_cv_ctime_args"; then
    AC_MSG_RESULT(no)
else
    if test "$ac_cv_ctime_args" = 2; then
        AC_DEFINE([HAVE_CTIME_R_2],[1],[Define if ctime_r is present with 2 parameters.])
    elif test "$ac_cv_ctime_args" = 3; then
        AC_DEFINE([HAVE_CTIME_R_3],[1],[Define if ctime_r is present with 3 parameters.])
    fi
    AC_MSG_RESULT([yes, and it takes $ac_cv_ctime_args arguments])
fi 

# output the underlying makefiles
WANT_SUBDIRS="doc configs shibsp"
AC_CONFIG_FILES([Makefile doc/Makefile configs/Makefile shibsp/Makefile])

#
# Build FastCGI support?
#
AC_MSG_CHECKING(for FastCGI support)
AC_ARG_WITH(fastcgi,
    AS_HELP_STRING([--with-fastcgi=DIR],[Build FastCGI support]),
    [WANT_FASTCGI=$withval],[WANT_FASTCGI=no])
AC_MSG_RESULT($WANT_FASTCGI)

if test "$WANT_FASTCGI" != "no"; then

    if test "$WANT_FASTCGI" != "yes"; then
        if test x_$WANT_FASTCGI != x_/usr; then
            FASTCGI_INCLUDE="-I$WANT_FASTCGI/include"
            FASTCGI_LDFLAGS="-L$WANT_FASTCGI/lib"
        fi
    fi

    # save and append master flags
    save_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$FASTCGI_INCLUDE $CPPFLAGS"

    AC_CHECK_HEADER([fcgio.h],,AC_MSG_ERROR([unable to find FastCGI header files]))
    FASTCGI_LIBS="-lfcgi -lfcgi++"

    # restore standard flags
    CPPFLAGS="$save_CPPFLAGS"
fi

AC_SUBST(FASTCGI_INCLUDE)
AC_SUBST(FASTCGI_LDFLAGS)
AC_SUBST(FASTCGI_LIBS)

# always output the Makefile, even if you don't use it
AC_CONFIG_FILES([fastcgi/Makefile])
AM_CONDITIONAL(BUILD_FASTCGI,test ! "$WANT_FASTCGI" = "no")

if test ! "$WANT_FASTCGI" = "no" ; then
    WANT_SUBDIRS="$WANT_SUBDIRS fastcgi"
fi


#
# If no --enable-apache-xx specified 
# find a default and fake the specific parameters
#

# simple macro to peek at an enable or a with
AC_DEFUN([Peek],
if test "[${[$1]_][$2]+set}" = set; then
  peekval="${[$1]_[$2]}"
  $3
fi; dnl
)

AC_MSG_CHECKING(if default apache needed)
need_default=yes
Peek(enable,apache_24,need_default=no)
AC_MSG_RESULT($need_default)

if test "$need_default" = "yes"; then
  # find an apxs, then the httpd
  xs=
  Peek(with,apxs24,xs="$peekval")
  if test "x$xs" = "x"; then
    AC_PATH_PROGS([xs], [apxs2 apxs],, [/usr/local/apache2/bin:/usr/local/apache/bin:/usr/sbin:$PATH])
    AS_IF([test "x$xs" = "x"], [AC_MSG_ERROR([No apxs, no Apache found. Try --with-apxs24, etc.])])
  fi
  # ask the daemon for the version and set parameters
  AC_MSG_CHECKING(default apache version)
  httpd="`$xs -q SBINDIR`/`$xs -q TARGET`"
  if test "x$httpd" != "x" && test -f $httpd ; then
     v=`$httpd -v|$SED -n -e 's/.*Apache\/\.*//p'`
     case $v in
       2.4*)   [enable_apache_24]=yes
               [with_apxs24]=$xs
               AC_MSG_RESULT(2.4)
               ;;
       *)      AC_MSG_ERROR([unusable Apache versions: $v. Try setting --with=apxs24, etc.])
     esac
  else 
     AC_MSG_RESULT([cannot determine Apache version. Try setting --with-apxs24, etc.])
  fi
fi

# Apache 2.4 (mod_shib_24)
#   --enable-apache-24
#   --with-apxs24     (DSO build, the normal way, uses apxs to derive build flags)
#   --with-apr1       (DSO build, APR development package installed separately)
#   --with-apu1       (DSO build, APR-UTIL development package installed separately)

AC_ARG_ENABLE(apache-24,
	AS_HELP_STRING([--enable-apache-24],[enable the Apache 2.4 module]),
	[if test "x$enableval" = "x" ; then
         WANT_APACHE_24=yes
	 else
	     WANT_APACHE_24="$enableval"
	 fi
	],[ WANT_APACHE_24=no ])
AC_MSG_CHECKING(whether to build Apache 2.4 module)
if test "$WANT_APACHE_24" != yes && test "$WANT_APACHE_24" != no ; then
    WANT_APACHE_24=yes
fi
AC_MSG_RESULT($WANT_APACHE_24)

if test "$WANT_APACHE_24" = "yes" ; then
    AC_ARG_WITH(apxs24, 
        AS_HELP_STRING([--with-apxs24=FILE],[Specifies where to find the Apache 2.4 apxs script.]),
        [
        AC_MSG_CHECKING(for user-specified Apache 2.4 apxs name/location)
        if test "$withval" != "no" ; then
          if test "$withval" != "yes"; then
            APXS24=$withval
            AC_MSG_RESULT("$withval")
          fi
        fi
        ],
        [
        AC_PATH_PROG(APXS24, apxs2, no)
        if test "$APXS24" = "no" ; then
            AC_PATH_PROG(APXS24, apxs, no)
        fi
        if test "$APXS24" = "no" ; then
          for i in /usr/sbin /usr/local/apache2/bin /usr/local/apache/bin /opt/local/bin ; do
            if test "$APXS24" = "no" && test -f "$i/apxs2" ; then
              APXS24="$i/apxs2"
            fi
          done
          if test "$APXS24" = "no" ; then
            for i in /usr/sbin /usr/local/apache2/bin /usr/local/apache/bin /opt/local/bin ; do
              if test "$APXS24" = "no" && test -f "$i/apxs" ; then
                APXS24="$i/apxs"
              fi
            done
          fi
        fi
        ])

    AC_MSG_CHECKING([to see if Apache 2.4 apxs was located])
    if test ! -f "$APXS24" ; then
        AC_MSG_RESULT(no)
        AC_MSG_ERROR([Unable to locate Apache 2.4 apxs script. An Apache development package may be missing from your server, or you may need to use the --with-apxs24 option.])
    fi
    AC_MSG_RESULT($APXS24)
    AC_SUBST(APXS24)

    # APR1 settings
    AC_ARG_WITH(apr1,
        AS_HELP_STRING([--with-apr1=PATH],[where apr-1-config is installed]),
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
        AC_PATH_PROG(APR1_CONFIG, apr-1-config,,[`$APXS24 -q SBINDIR`]:[$PATH])
        ])
    if test -f "${APR1_CONFIG}"; then
        APR1_INCLUDE="`${APR1_CONFIG} --includes`"
        APR1_CFLAGS="`${APR1_CONFIG} --cflags` `${APR1_CONFIG} --cppflags`"
        APR1_LDFLAGS="`${APR1_CONFIG} --ldflags`"
        APR1_LIBS="`${APR1_CONFIG} --link-libtool --libs`"
    else
        AC_MSG_ERROR([Unable to locate apr-1-config, may need --with-apr1 option.])
    fi

    # APU1 settings
    AC_ARG_WITH(apu1,
        AS_HELP_STRING([--with-apu1=PATH],[where apu-1-config is installed]),
        [
        AC_MSG_CHECKING(for user-specified apu-1-config name/location)
        if test "$withval" != "no" ; then
            if test "$withval" != "yes"; then
                APU1_CONFIG=$withval
                AC_MSG_RESULT("$withval")
            fi
        fi
        ],
        [
        AC_PATH_PROG(APU1_CONFIG, apu-1-config,,[`$APXS24 -q SBINDIR`]:[$PATH])
        ])
    if test -f "${APU1_CONFIG}"; then
        APU1_INCLUDE="`${APU1_CONFIG} --includes`"
        APU1_LDFLAGS="`${APU1_CONFIG} --ldflags`"
        APU1_LIBS="`${APU1_CONFIG} --link-libtool --libs`"
    else
        AC_MSG_ERROR([Unable to locate apu-1-config, may need --with-apu1 option.])
    fi
    
    # extract settings we need from APXS24 -q
    APXS24_CC="`$APXS24 -q CC`"
    APXS24_CFLAGS="`$APXS24 -q CPPFLAGS` `$APXS24 -q CFLAGS` $APR1_CFLAGS"
    APXS24_INCLUDE="-I`$APXS24 -q INCLUDEDIR` $APR1_INCLUDE $APU1_INCLUDE"
    APXS24_LDFLAGS="`$APXS24 -q LDFLAGS` $APR1_LDFLAGS $APU1_LDFLAGS"
    APXS24_LIBS="`$APXS24 -q LIBS` $APR1_LIBS $APU1_LIBS"
fi

AC_SUBST(APXS24_CFLAGS)
AC_SUBST(APXS24_INCLUDE)
AC_SUBST(APXS24_LDFLAGS)
AC_SUBST(APXS24_LIBS)

# always output the Makefile, even if you don't use it
AC_CONFIG_FILES([apache/Makefile])
AM_CONDITIONAL(BUILD_AP24,test "$WANT_APACHE_24" = "yes")

# add the apache module to the list of wanted subdirs..
if test "$WANT_APACHE_24" = "yes" ; then
    WANT_SUBDIRS="$WANT_SUBDIRS apache"
fi

# Check for unit test support
AC_CONFIG_FILES([tests/Makefile])
WANT_SUBDIRS="$WANT_SUBDIRS tests"

AC_SUBST(WANT_SUBDIRS)

if test -n "$APXS24_CC" && test "$APXS24_CC" != "$CC" ; then
  echo "=================================================================="
  echo "WARNING: You have chosen to compile Apache-2.4 modules with a different"
  echo "         compiler than the one used to compile Apache."
  echo ""
  echo "    Current compiler:      $CC"
  echo "   Apache's compiler:      $APXS24_CC"
  echo ""
  echo "This could cause problems."
  echo "=================================================================="
fi

AC_OUTPUT

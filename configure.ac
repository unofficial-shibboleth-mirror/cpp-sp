AC_PREREQ([2.50])
AC_INIT([shibboleth],[3.5.2],[https://shibboleth.atlassian.net/jira],[shibboleth-sp])
AC_CONFIG_SRCDIR(shibsp)
AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_MACRO_DIR(m4)
AM_INIT_AUTOMAKE
PKG_INSTALLDIR

# Docygen features
DX_HTML_FEATURE(ON)
DX_DOT_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN(shibboleth, doxygen.cfg, doc/api)
DX_INCLUDE=

AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug],[Produce debug variant (Default = no)]),
    enable_debug=$enableval, enable_debug=no)

if test "$enable_debug" = "yes" ; then
    AM_CFLAGS="-D_DEBUG"
    AM_CXXFLAGS="-D_DEBUG"
fi

AC_CONFIG_HEADERS([config.h shibsp/config_pub.h])
AC_CONFIG_FILES([shibsp.pc shibsp-lite.pc shibboleth.spec])

AC_PROG_CC([gcc gcc3 cc])
AC_PROG_CXX([g++ g++3 c++ CC])

if test "$GCC" = "yes" ; then
    AM_CFLAGS="$AM_CFLAGS -Wall -W"
    AM_CXXFLAGS="$AM_CXXFLAGS -Wall -W"
fi

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

AC_CACHE_CHECK([for SOCK_CLOEXEC support], [shib_cv_sock_cloexec],
[AC_TRY_RUN([
#include <sys/types.h>
#include <sys/socket.h>
int main()
{
return socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0) == -1;
}], [shib_cv_sock_cloexec=yes], [shib_cv_sock_cloexec=no], [shib_cv_sock_cloexec=no])])

if test "$shib_cv_sock_cloexec" = "yes"; then
	AC_DEFINE([HAVE_SOCK_CLOEXEC], 1, [Define if the SOCK_CLOEXEC flag is supported])
fi

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

# Boost
BOOST_REQUIRE
BOOST_BIND
BOOST_LAMBDA
BOOST_POINTER_CONTAINER
BOOST_SMART_PTR
BOOST_STRING_ALGO
BOOST_TUPLE

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

AX_PKG_CHECK_MODULES([log4shib],,[log4shib],
    [AC_DEFINE([SHIBSP_LOG4SHIB],[1],[Define to 1 if log4shib library is used.])],
    [AX_PKG_CHECK_MODULES([log4cpp],,[log4cpp],
        [AC_DEFINE([SHIBSP_LOG4CPP],[1],[Define to 1 if log4cpp library is used.])],,
        [SHIBSP_LITE_REQUIRES],[SHIBSP_LITE_REQUIRES_PRIVATE])],,
    [SHIBSP_LITE_REQUIRES],[SHIBSP_LITE_REQUIRES_PRIVATE])

AX_PKG_CHECK_MODULES([xerces],,[xerces-c >= 3.2],,,
    [SHIBSP_LITE_REQUIRES],[SHIBSP_LITE_REQUIRES_PRIVATE])

AX_PKG_CHECK_MODULES([xmlsec],,[xml-security-c >= 2],,,
    [SHIBSP_REQUIRES],[SHIBSP_REQUIRES_PRIVATE])

AX_PKG_CHECK_MODULES([xmltooling],,[xmltooling >= 3.1],,,
    [SHIBSP_REQUIRES],[SHIBSP_REQUIRES_PRIVATE])
PKG_CHECK_VAR([xmltooling_includedir],[xmltooling],[includedir])
PKG_CHECK_VAR([XMLTOOLINGXMLDIR],[xmltooling],[pkgxmldir])
DX_INCLUDE="$DX_INCLUDE $xmltooling_includedir"

AX_PKG_CHECK_MODULES([xmltooling_lite],,[xmltooling-lite >= 3.1],,,
    [SHIBSP_LITE_REQUIRES],[SHIBSP_LITE_REQUIRES_PRIVATE])

AX_PKG_CHECK_MODULES([opensaml],,[opensaml >= 3.1],,,
    [SHIBSP_REQUIRES],[SHIBSP_REQUIRES_PRIVATE])
PKG_CHECK_VAR([OPENSAMLXMLDIR],[opensaml],[pkgxmldir])

# output the underlying makefiles
WANT_SUBDIRS="doc schemas configs shibsp plugins shibd util"
AC_CONFIG_FILES([Makefile doc/Makefile schemas/Makefile \
	configs/Makefile shibsp/Makefile plugins/Makefile \
	shibd/Makefile util/Makefile selinux/Makefile])

## ADFS?
AC_CONFIG_FILES([adfs/Makefile])
AC_ARG_ENABLE([adfs],
    AS_HELP_STRING([--disable-adfs],[do not build the ADFS module]),
    [adfs_enabled=$enableval], [adfs_enabled=yes])
if test "x$adfs_enabled" = "x" ; then
    adfs_enabled=yes
fi
AC_MSG_CHECKING(whether to build the ADFS module)
if test "$adfs_enabled" = "no" ; then
    AC_MSG_RESULT(no)
else
    AC_MSG_RESULT(yes)
    WANT_SUBDIRS="$WANT_SUBDIRS adfs"
fi

## systemd
dnl Systemd will be disabled by default and requires you to run configure with
dnl --enable-systemd to look for and enable systemd.
AC_ARG_ENABLE(systemd,
    AS_HELP_STRING([--enable-systemd],[Build with systemd (Default = no)]),
    [AS_IF([test "x$enableval" != xno],
        [PKG_CHECK_MODULES([SYSTEMD],[libsystemd],,[PKG_CHECK_MODULES([SYSTEMD],[libsystemd-daemon])])
	 # because in systemd 209 the libraries were merged into a single libsystemd.
	 # sd_notify() is always present, no need to check for it:
         AC_DEFINE([HAVE_SD_NOTIFY],[1],[Define to 1 if you have the sd_notify function.])])])

#
# Build NSAPI module?
#
AC_MSG_CHECKING(for NSAPI module option)
AC_ARG_WITH(nsapi,
    AS_HELP_STRING([--with-nsapi=DIR],[Build NSAPI module for Netscape/iPlanet/SunONE]),
    [WANT_NSAPI=$withval],[WANT_NSAPI=no])
AC_MSG_RESULT($WANT_NSAPI)

if test "$WANT_NSAPI" != "no"; then
  if test ! -d $WANT_NSAPI/bin ; then
    AC_MSG_ERROR([Please specify the path to the root of your Netscape/iPlanet/SunONE server using --with-nsapi=DIR])
  fi
  AC_MSG_CHECKING(for NSAPI include files)
  if test -d $WANT_NSAPI/include ; then
    NSAPI_INCLUDE=$WANT_NSAPI/include
    AC_MSG_RESULT(Netscape-Enterprise 3.x style)
    AC_CHECK_HEADERS([$NSAPI_INCLUDE/nsapi.h],,,[#define XP_UNIX])
    NSAPI_INCLUDE="$NSAPI_INC_DIR -I$NSAPI_INCLUDE"
  fi
  if test -d $WANT_NSAPI/plugins/include ; then
    test -n "$NSAPI_INCLUDE" && NSAPI_INC_DIR="-I$NSAPI_INCLUDE"
    NSAPI_INCLUDE="$WANT_NSAPI/plugins/include"
    AC_MSG_RESULT(iPlanet 4.x / SunONE 6.x style)
    AC_CHECK_HEADERS([$NSAPI_INCLUDE/nsapi.h],,,[#define XP_UNIX])
    NSAPI_INCLUDE="$NSAPI_INC_DIR -I$NSAPI_INCLUDE"
  fi
  if test "$NSAPI_INCLUDE" = ""; then
    AC_MSG_ERROR([Please check you have nsapi.h in either $WANT_NSAPI/include or $WANT_NSAPI/plugins/include])
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
# Build Memcached support?
#
AC_MSG_CHECKING(for Memcached support)
AC_ARG_WITH(memcached,
    AS_HELP_STRING([--with-memcached=DIR],[Build Memcached support]),
    [WANT_MEMCACHED=$withval],[WANT_MEMCACHED=no])
AC_MSG_RESULT($WANT_MEMCACHED)

if test "$WANT_MEMCACHED" != "no"; then

    if test "$WANT_MEMCACHED" != "yes"; then
        if test x_$WANT_MEMCACHED != x_/usr; then
            MEMCACHED_INCLUDE="-I$WANT_MEMCACHED/include"
            MEMCACHED_LDFLAGS="-L$WANT_MEMCACHED/lib"
        fi
    fi

    # save and append master flags
    save_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$MEMCACHED_INCLUDE $CPPFLAGS"    

    AC_CHECK_HEADER([libmemcached/memcached.h],,
        AC_MSG_ERROR([unable to find Memcached header files]))
    AC_CHECK_DECL([memcached_last_error_message],
        [AC_DEFINE([HAVE_MEMCACHED_LAST_ERROR_MESSAGE],[1],[Define to 1 if libmemcached supports error handling function.])],,
        [#include <libmemcached/memcached.h>])
    MEMCACHED_LIBS="-lmemcached"

    # restore standard flags
    CPPFLAGS="$save_CPPFLAGS"
fi

AC_SUBST(MEMCACHED_INCLUDE)
AC_SUBST(MEMCACHED_LDFLAGS)
AC_SUBST(MEMCACHED_LIBS)

# always output the Makefile, even if you don't use it
AC_CONFIG_FILES([memcache-store/Makefile])
AM_CONDITIONAL(BUILD_MEMCACHED,test ! "$WANT_MEMCACHED" = "no")

if test ! "$WANT_MEMCACHED" = "no" ; then
    WANT_SUBDIRS="$WANT_SUBDIRS memcache-store"
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
Peek(enable,apache_13,need_default=no)
Peek(enable,apache_20,need_default=no)
Peek(enable,apache_22,need_default=no)
Peek(enable,apache_24,need_default=no)
AC_MSG_RESULT($need_default)

if test "$need_default" = "yes"; then
  # find an apxs, then the httpd
  xs=
  Peek(with,apxs,xs="$peekval")
  Peek(with,apxs2,xs="$peekval")
  Peek(with,apxs22,xs="$peekval")
  Peek(with,apxs24,xs="$peekval")
  if test "x$xs" = "x"; then
    AC_PATH_PROGS([xs], [apxs2 apxs],, [/usr/local/apache2/bin:/usr/local/apache/bin:/usr/sbin:$PATH])
    AS_IF([test "x$xs" = "x"], [AC_MSG_ERROR([No apxs, no Apache found. Try --with-apxs, --with-apxs2, etc.])])
  fi
  # ask the daemon for the version and set parameters
  AC_MSG_CHECKING(default apache version)
  httpd="`$xs -q SBINDIR`/`$xs -q TARGET`"
  if test "x$httpd" != "x" && test -f $httpd ; then
     v=`$httpd -v|$SED -n -e 's/.*Apache\/\.*//p'`
     case $v in
       1.3*)   [enable_apache_13]=yes
               [with_apxs]=$xs
               AC_MSG_RESULT(1.3)
               ;;
       2.0*)   [enable_apache_20]=yes
               [with_apxs2]=$xs
               AC_MSG_RESULT(2.0)
               ;;
       2.2*)   [enable_apache_22]=yes
               [with_apxs22]=$xs
               AC_MSG_RESULT(2.2)
               ;;
       2.4*)   [enable_apache_24]=yes
               [with_apxs24]=$xs
               AC_MSG_RESULT(2.4)
               ;;
       *)      AC_MSG_ERROR([unusable Apache versions: $v. Try setting --with-apxs, --with=apxs2, etc.])
     esac
  else 
     AC_MSG_RESULT([cannot determine Apache version. Try setting --with-apxs, --with-apxs2, etc.])
  fi
fi

# Apache 1.3 (mod_shib_13)
#   --enable-apache-13
#   --with-apxs      (DSO build, the normal way, uses apxs to derive build flags)

AC_ARG_ENABLE(apache-13,
	AS_HELP_STRING([--enable-apache-13],[enable the Apache 1.3 module]),
	[if test "x$enableval" = "x" ; then
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
        AS_HELP_STRING([--with-apxs=FILE],[Specifies where to find the Apache 1.3 apxs script.]),
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
          for i in /usr/sbin /usr/local/apache/bin /opt/local/bin ; do
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
    APXS_CFLAGS="`$APXS -q CFLAGS` `$APXS -q CFLAGS_SHLIB`"
    APXS_INCLUDE="-I`$APXS -q INCLUDEDIR`"
    APXS_LDFLAGS="`$APXS -q LDFLAGS`"
fi

AC_SUBST(APXS_CFLAGS)
AC_SUBST(APXS_INCLUDE)
AC_SUBST(APXS_LDFLAGS)

# Apache 2.0 (mod_shib_20)
#   --enable-apache-20
#   --with-apxs2      (DSO build, the normal way, uses apxs to derive build flags)
#   --with-apr        (DSO build, APR development package installed separately)
#   --with-apu        (DSO build, APR-UTIL development package installed separately)

AC_ARG_ENABLE(apache-20,
	AS_HELP_STRING([--enable-apache-20],[enable the Apache 2.0 module]),
	[if test "x$enableval" = "x" ; then
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
        AS_HELP_STRING([--with-apxs2=FILE],[Specifies where to find the Apache 2.0 apxs script.]),
        [
        AC_MSG_CHECKING(for user-specified Apache 2.0 apxs name/location)
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
          for i in /usr/sbin /usr/local/apache2/bin /usr/local/apache/bin /opt/local/bin ; do
            if test "$APXS2" = "no" && test -f "$i/apxs2" ; then
              APXS2="$i/apxs2"
            fi
          done
          if test "$APXS2" = "no" ; then
            for i in /usr/sbin /usr/local/apache2/bin /usr/local/apache/bin /opt/local/bin ; do
              if test "$APXS2" = "no" && test -f "$i/apxs" ; then
                APXS2="$i/apxs"
              fi
            done
          fi
        fi
        ])

    AC_MSG_CHECKING([to see if Apache 2.0 apxs was located])
    if test ! -f "$APXS2" ; then
        AC_MSG_RESULT(no)
        AC_MSG_ERROR([Unable to locate Apache 2.0 apxs script. An Apache development package may be missing from your server, or you may need to use the --with-apxs2 option.])
    fi
    AC_MSG_RESULT($APXS2)
    AC_SUBST(APXS2)

    # APR settings
    AC_ARG_WITH(apr, 
        AS_HELP_STRING([--with-apr=PATH],[where apr-config is installed]),
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
        AC_PATH_PROG(APR_CONFIG, apr-config,,[`$APXS2 -q SBINDIR`]:[$PATH])
        ])
    if test -f "${APR_CONFIG}"; then
        APR_INCLUDE="`${APR_CONFIG} --includes`"
        APR_CFLAGS="`${APR_CONFIG} --cflags` `${APR_CONFIG} --cppflags`"
        APR_LDFLAGS="`${APR_CONFIG} --ldflags`"
        APR_LIBS="`${APR_CONFIG} --link-libtool --libs`"
    else
        AC_MSG_ERROR([Unable to locate apr-config, may need --with-apr option.])
    fi

    # APU settings
    AC_ARG_WITH(apu, 
        AS_HELP_STRING([--with-apu=PATH],[where apu-config is installed]),
        [
        AC_MSG_CHECKING(for user-specified apu-config name/location)
        if test "$withval" != "no" ; then
            if test "$withval" != "yes"; then
                APU_CONFIG=$withval
                AC_MSG_RESULT("$withval")
            fi
        fi
        ],
        [
        AC_PATH_PROG(APU_CONFIG, apu-config,,[`$APXS2 -q SBINDIR`]:[$PATH])
        ])
    if test -f "${APU_CONFIG}"; then
        APU_INCLUDE="`${APU_CONFIG} --includes`"
        APU_LDFLAGS="`${APU_CONFIG} --ldflags`"
        APU_LIBS="`${APU_CONFIG} --link-libtool --libs`"
    else
        AC_MSG_ERROR([Unable to locate apu-config, may need --with-apu option.])
    fi

    # extract settings we need from APXS2 -q
    APXS2_CC="`$APXS2 -q CC`"
    APXS2_CFLAGS="`$APXS2 -q CPPFLAGS` `$APXS2 -q CFLAGS` $APR_CFLAGS"
    APXS2_INCLUDE="-I`$APXS2 -q INCLUDEDIR` $APR_INCLUDE $APU_INCLUDE"
    APXS2_LDFLAGS="`$APXS2 -q LDFLAGS` $APR_LDFLAGS $APU_LDFLAGS"
    APXS2_LIBS="`$APXS2 -q LIBS` $APR_LIBS $APU_LIBS"
fi

AC_SUBST(APXS2_CFLAGS)
AC_SUBST(APXS2_INCLUDE)
AC_SUBST(APXS2_LDFLAGS)
AC_SUBST(APXS2_LIBS)


# Apache 2.2 (mod_shib_22)
#   --enable-apache-22
#   --with-apxs22     (DSO build, the normal way, uses apxs to derive build flags)
#   --with-apr1       (DSO build, APR development package installed separately)
#   --with-apu1       (DSO build, APR-UTIL development package installed separately)

AC_ARG_ENABLE(apache-22,
	AS_HELP_STRING([--enable-apache-22],[enable the Apache 2.2 module]),
	[if test "x$enableval" = "x" ; then
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
        AS_HELP_STRING([--with-apxs22=FILE],[Specifies where to find the Apache 2.2 apxs script.]),
        [
        AC_MSG_CHECKING(for user-specified Apache 2.2 apxs name/location)
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
          for i in /usr/sbin /usr/local/apache2/bin /usr/local/apache/bin /opt/local/bin ; do
            if test "$APXS22" = "no" && test -f "$i/apxs2" ; then
              APXS22="$i/apxs2"
            fi
          done
          if test "$APXS22" = "no" ; then
            for i in /usr/sbin /usr/local/apache2/bin /usr/local/apache/bin /opt/local/bin ; do
              if test "$APXS22" = "no" && test -f "$i/apxs" ; then
                APXS22="$i/apxs"
              fi
            done
          fi
        fi
        ])

    AC_MSG_CHECKING([to see if Apache 2.2 apxs was located])
    if test ! -f "$APXS22" ; then
        AC_MSG_RESULT(no)
        AC_MSG_ERROR([Unable to locate Apache 2.2 apxs script. An Apache development package may be missing from your server, or you may need to use the --with-apxs22 option.])
    fi
    AC_MSG_RESULT($APXS22)
    AC_SUBST(APXS22)

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
        AC_PATH_PROG(APR1_CONFIG, apr-1-config,,[`$APXS22 -q SBINDIR`]:[$PATH])
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
        AC_PATH_PROG(APU1_CONFIG, apu-1-config,,[`$APXS22 -q SBINDIR`]:[$PATH])
        ])
    if test -f "${APU1_CONFIG}"; then
        APU1_INCLUDE="`${APU1_CONFIG} --includes`"
        APU1_LDFLAGS="`${APU1_CONFIG} --ldflags`"
        APU1_LIBS="`${APU1_CONFIG} --link-libtool --libs`"
    else
        AC_MSG_ERROR([Unable to locate apu-1-config, may need --with-apu1 option.])
    fi

    # extract settings we need from APXS22 -q
    APXS22_CC="`$APXS22 -q CC`"
    APXS22_CFLAGS="`$APXS22 -q CPPFLAGS` `$APXS22 -q CFLAGS` $APR1_CFLAGS"
    APXS22_INCLUDE="-I`$APXS22 -q INCLUDEDIR` $APR1_INCLUDE $APU1_INCLUDE"
    APXS22_LDFLAGS="`$APXS22 -q LDFLAGS` $APR1_LDFLAGS $APU1_LDFLAGS"
    APXS22_LIBS="`$APXS22 -q LIBS` $APR1_LIBS $APU1_LIBS"
fi

AC_SUBST(APXS22_CFLAGS)
AC_SUBST(APXS22_INCLUDE)
AC_SUBST(APXS22_LDFLAGS)
AC_SUBST(APXS22_LIBS)

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

    # If we haven't done this work already for Apache 2.2
    if test "$WANT_APACHE_22" != "yes" ; then
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
AM_CONDITIONAL(BUILD_AP13,test "$WANT_APACHE_13" = "yes")
AM_CONDITIONAL(BUILD_AP20,test "$WANT_APACHE_20" = "yes")
AM_CONDITIONAL(BUILD_AP22,test "$WANT_APACHE_22" = "yes")
AM_CONDITIONAL(BUILD_AP24,test "$WANT_APACHE_24" = "yes")

# add the apache module to the list of wanted subdirs..
if test "$WANT_APACHE_13" = "yes" || test "$WANT_APACHE_20" = "yes" || test "$WANT_APACHE_22" = "yes" || test "$WANT_APACHE_24" = "yes" ; then
    WANT_SUBDIRS="$WANT_SUBDIRS apache"
fi


#
# Implement the checks of the ODBC Storage Service
#
# 1) Assume the user wants ODBC; if it's not found then just continue without
# 2) If the user specifically requested odbc, look for it and ERROR if not found
# 3) If the user specifically requested no odbc, don't build it.
#

AC_CONFIG_FILES([odbc-store/Makefile])

# determine whether we should enable the odbc ccache
AC_ARG_ENABLE([odbc],
	AS_HELP_STRING([--disable-odbc],[disable the ODBC Storage Service]),
	[odbc_enabled=$enableval], [odbc_enabled=default])
if test "x$odbc_enabled" = "x" ; then
    odbc_enabled=yes
fi

# Are we trying to build ODBC?
AC_MSG_CHECKING(whether to build the ODBC storage service)
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
	   AS_HELP_STRING([--with-odbc=PATH],[directory where odbc is installed]),
	    [if test "$with_odbc" = no ; then
            AC_MSG_ERROR([Try running --disable-odbc instead.])
         elif test "$with_odbc" != yes ; then
            odbc_dir="$with_odbc/bin"
            if test "$with_odbc" != /usr ; then
                ODBC_CFLAGS="-I$with_odbc/include"
                ODBC_LIBS="-L$with_odbc/lib"
            fi
         fi])

   AC_PATH_PROG(ODBC_CONFIG, odbc_config, no, $odbc_dir $PATH )
   if test "$ODBC_CONFIG" = no ; then
      AC_MSG_WARN([Cannot find odbc_config, will try to guess settings.])
      ODBC_LIBS="$ODBC_LIBS -lodbc"
   else
      ODBC_CFLAGS=`$ODBC_CONFIG --cflags`
      ODBC_LIBS=`$ODBC_CONFIG --libs`
   fi

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
      AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([[#include <sql.h>
 #include <sqlext.h>
 #include <stdio.h>]],
            [[SQLSetEnvAttr(SQL_NULL_HANDLE, SQL_ATTR_CONNECTION_POOLING, (void*)SQL_CP_ONE_PER_HENV, 0)]])],
        [have_odbc_libs=yes],[have_odbc_libs=no])
      LIBS="$save_LIBS"
      if test "$have_odbc_libs" = no ; then
         if test "$odbc_enabled" = "yes" ; then
            AC_MSG_ERROR([unable to link with ODBC Library])
         else
            AC_MSG_RESULT([no, skipping ODBC])
         fi
      fi
   fi

   CPPFLAGS="$save_CPPFLAGS"
fi

# if have_odbc_libs=yes then go ahead with building ODBC
if test "$have_odbc_libs" = yes ; then
   # this AC_MSG_RESULT is from above!
   AC_MSG_RESULT(yes)
   WANT_SUBDIRS="$WANT_SUBDIRS odbc-store"
   AC_SUBST(ODBC_CFLAGS)
   AC_SUBST(ODBC_LIBS)
fi

AC_ARG_WITH([gssapi],
  [AS_HELP_STRING([--with-gssapi],[include GSSAPI support])],,[with_gssapi=check])
AS_IF([test "x$with_gssapi" != xno],
  [AX_PKG_CHECK_MODULES([gss],,[krb5-gssapi],
     [PKG_CHECK_VAR([GSS_VENDOR],[krb5-gssapi],[vendor])
      AS_CASE(["$GSS_VENDOR"],
        [Heimdal],[AC_DEFINE([SHIBSP_HAVE_GSSHEIMDAL],[1],[if you have the Heimdal gssapi libraries])],
        [MIT],[AC_DEFINE([SHIBSP_HAVE_GSSMIT],[1],[if you have the MIT gssapi libraries])])],
     [AX_PKG_CHECK_MODULES([gnu_gss],,[gss],
        [AC_DEFINE([SHIBSP_HAVE_GSSGNU],[1],[if you have the GNU gssapi libraries])],
        [with_gssapi=no],
        [SHIBSP_LITE_REQUIRES],[SHIBSP_LITE_REQUIRES_PRIVATE])],
     [SHIBSP_LITE_REQUIRES],[SHIBSP_LITE_REQUIRES_PRIVATE])
   AS_IF([test "x$with_gssapi" != xno],
     [AC_DEFINE([SHIBSP_HAVE_GSSAPI],[1],[if you have the gssapi libraries])
      AX_SAVE_FLAGS
        CXXFLAGS="$gss_CFLAGS $gnu_gss_CFLAGS $CXXFLAGS"
        LIBS="$gss_LIBS $gnu_gss_LIBS $LIBS"
      AC_CHECK_DECLS([gss_get_name_attribute,GSS_C_NT_EXPORT_NAME_COMPOSITE],,,[[
#ifdef SHIBSP_HAVE_GSSGNU
# include <gss.h>
#elif defined SHIBSP_HAVE_GSSMIT
# include <gssapi/gssapi.h>
# include <gssapi/gssapi_ext.h>
#else
# include <gssapi.h>
#endif
]])
      AX_RESTORE_FLAGS
     ])
  ])
AM_CONDITIONAL([GSSAPI_NAMINGEXTS],[test "x$ac_cv_have_decl_gss_get_name_attribute" = xyes])

# Check for unit test support
AC_CONFIG_FILES([unittests/Makefile])
AC_ARG_VAR([CXXTEST], [override the cxxtestgen executable and options])
AC_CHECK_PROGS([CXXTEST], [cxxtestgen cxxtestgen.pl], [false])
AC_ARG_VAR([CXXTESTFLAGS], [override the cxxtest compiler flags needed to build tests])
AM_CONDITIONAL([BUILD_UNITTEST], [test "x${CXXTEST}" != xfalse])
WANT_SUBDIRS="$WANT_SUBDIRS unittests"

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
  echo "WARNING: You have chosen to compile Apache-2.0 modules with a different"
  echo "         compiler than the one used to compile Apache."
  echo ""
  echo "    Current compiler:      $CC"
  echo "   Apache's compiler:      $APXS2_CC"
  echo ""
  echo "This could cause problems."
  echo "=================================================================="
fi

if test -n "$APXS22_CC" && test "$APXS22_CC" != "$CC" ; then
  echo "=================================================================="
  echo "WARNING: You have chosen to compile Apache-2.2 modules with a different"
  echo "         compiler than the one used to compile Apache."
  echo ""
  echo "    Current compiler:      $CC"
  echo "   Apache's compiler:      $APXS22_CC"
  echo ""
  echo "This could cause problems."
  echo "=================================================================="
fi

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

dnl @synopsis AC_CXX_NAMESPACES
dnl
dnl If the compiler can prevent names clashes using namespaces, define
dnl HAVE_NAMESPACES.
dnl
dnl @author Luc Maisonobe
dnl
AC_DEFUN([AC_CXX_NAMESPACES],
[AC_CACHE_CHECK(whether the compiler implements namespaces,
ac_cv_cxx_namespaces,
[
 AC_LANG_PUSH([C++])
 AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[namespace Outer { namespace Inner { int i = 0; }}]], [[using namespace Outer::Inner; return i;]])],[ac_cv_cxx_namespaces=yes],[ac_cv_cxx_namespaces=no])
 AC_LANG_POP([])
])
if test "$ac_cv_cxx_namespaces" = yes; then
  AC_DEFINE(HAVE_NAMESPACES,1,[define if the compiler implements namespaces])
fi
])


dnl
dnl @author Luc Maisonobe
dnl
AC_DEFUN([AC_CXX_REQUIRE_STL],
[AC_CACHE_CHECK(whether the compiler supports Standard Template Library,
ac_cv_cxx_have_stl,
[AC_REQUIRE([AC_CXX_NAMESPACES])
 AC_LANG_PUSH([C++])
 AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <list>
#include <deque>
#ifdef HAVE_NAMESPACES
using namespace std;
#endif]], [[list<int> x; x.push_back(5);
list<int>::iterator iter = x.begin(); if (iter != x.end()) ++iter; return 0;]])],[ac_cv_cxx_have_stl=yes],[ac_cv_cxx_have_stl=no])
 AC_LANG_POP([])
])
if test "x_$ac_cv_cxx_have_stl" != x_yes; then
  AC_MSG_ERROR([C++ Standard Template Libary unsupported])
fi
])

dnl Determine whether we have gcc of a particular version or later,
dnl based on major, minor, patchlevel versions and date.
dnl AC_HAVE_GCC_VERSION(MAJOR_VERSION, MINOR_VERSION, PATCH_LEVEL, 
dnl 	SNAPSHOT_DATE [, ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]])
AC_DEFUN(AC_HAVE_GCC_VERSION,
[AC_CACHE_CHECK([gcc is at least version $1.$2.$3.$4],
          ac_cv_gcc_version_$1_$2_$3_$4,
[
  if test x$GCC = x ; then ac_cv_gcc_version_$1_$2_$3_$4=no
  else 
    ac_gcc_date=`$CC -v 2>&1 | grep '^gcc version ' | sed 's/ (.*//; s/.* //'`
    if test 0$ac_gcc_date -eq 0 ; then ac_gcc_date=0 ; fi
    AC_EGREP_CPP(yes, [#define HAVE_GCC_VERSION(MAJOR, MINOR, MICRO, DATE) \
    (__GNUC__ > (MAJOR) \
     || (__GNUC__ == (MAJOR) && __GNUC_MINOR__ > (MINOR)) \
     || (__GNUC__ == (MAJOR) && __GNUC_MINOR__ == (MINOR) \
         && __GNUC_PATCHLEVEL__ > (MICRO)) \
     || (__GNUC__ == (MAJOR) && __GNUC_MINOR__ == (MINOR) \
         && __GNUC_PATCHLEVEL__ == (MICRO) && ${ac_gcc_date}L >= (DATE)))
#if HAVE_GCC_VERSION($1,$2,$3,$4)
yes
#endif],
   AC_DEFINE_UNQUOTED(HAVE_GCC_VERSION_$1_$2_$3_$4, 1,
     [Define to 1 if we have gcc $1.$2.$3 ($4)])
   ac_cv_gcc_version_$1_$2_$3_$4=yes ; $5,
   ac_cv_gcc_version_$1_$2_$3_$4=no ; $6)
fi
])])dnl


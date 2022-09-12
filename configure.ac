AC_INIT([everarch], [0.1.0], [markus.peroebner@gmail.com])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/evr-glacier-storage.c])
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC

AC_PROG_LEX
if test "x$LEX" == "x:"
then
  AC_MSG_ERROR(flex was not found.)
fi

AC_PROG_YACC
PKG_PROG_PKG_CONFIG
AM_PATH_PYTHON([3.0])

AC_DEFINE(_DEFAULT_SOURCE, 1, This macro can be defined to ensure that the "default" definitions are provided.)
AC_DEFINE(_POSIX_C_SOURCE, 200809L, We want to use for example strnlen)
AC_DEFINE(_GNU_SOURCE, 1, We use for example fcntl's F_GETSIG)
AC_DEFINE(EVR_GCRY_MIN_VERSION, "1.8.0", Minimum version required for libgrcy)

AC_ARG_ENABLE(
  [futile-claim-set-tracking],
  [AS_HELP_STRING([--enable-futile-claim-set-tracking], [Enables tracking of claim-sets without any effect to the attr-index. Helpful for finding custom claims which are missing in the transformation.])],
  [AC_DEFINE([EVR_FUTILE_CLAIM_SET_TRACKING], [1], [Enables futile claim set tracking.])],
)

AC_ARG_ENABLE(
  [profile-sql-statements],
  [AS_HELP_STRING([--enable-profile-sql-statements], [Enables debug level logging of SQL statement step execution times. These log statements start with the message "sqlite statement duration". You can use the sqlite-prof.py script in this repository to aggregate the results.])],
  [AC_DEFINE([EVR_PROFILE_SQLITE_STMTS], [1], [Enables sqlite statement profiling.])],
)

AC_ARG_ENABLE(
  [profile-glacier],
  [AS_HELP_STRING([--enable-profile-glacier], [Enables debug level logging of glacier operation execution durations. These log statements start with the message "glacier operation duration".])],
  [AC_DEFINE([EVR_PROFILE_GLACIER_STMTS], [1], [Enables glacier operation profiling.])],
)

AC_DEFINE([EVR_LOG_INFO], [1], [Turns on log message output on level info.])
AC_ARG_ENABLE(
  [log-debug],
  [AS_HELP_STRING([--enable-log-debug], [Enables debug level logging.])],
  [AC_DEFINE([EVR_LOG_DEBUG], [1], [Turns on log message output on level debug.])],
)

if test x$prefix = xNONE ; then
  prefix=${ac_default_prefix}
fi

AC_DEFINE_UNQUOTED([EVR_PREFIX], ["${prefix}"], [Path prefix where everarch will be installed])

AC_STDC_HEADERS
AC_HAVE_HEADERS(string.h)

AC_FUNC_ALLOCA

AC_CHECK_HEADERS([sys/endian.h])
AC_CHECK_DECLS([be32toh htobe32], [], [],
[AC_INCLUDES_DEFAULT
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
])

AC_CHECK_FUNCS_ONCE([mkdtemp])

AX_PTHREAD

m4_ifdef([AM_PATH_LIBGCRYPT],[
    AM_PATH_LIBGCRYPT("1.8.0", , [AC_MSG_ERROR([gcrypt was not found in a sufficient version.])])
  ],
  AC_MSG_ERROR([automake gcrypt support is missing.])
)

PKG_CHECK_MODULES([EVERARCH], [
    sqlite3
])

AM_PATH_GPGME(1, , AC_MSG_ERROR(GnuPG Made Easy library not found))

PKG_CHECK_MODULES([XML], [libxml-2.0 >= 2.9])
PKG_CHECK_MODULES([XSLT], [libxslt >= 1.1])
PKG_CHECK_MODULES([SSL], [libssl >= 1.1 libcrypto >= 1.1])

AC_DEFINE(FUSE_USE_VERSION, 34, Fuse target API version.)
PKG_CHECK_MODULES([FUSE], [fuse3 >= 3.0])

AM_PATH_LISPDIR()

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
    Makefile
    src/Makefile
    python/Makefile
    emacs/Makefile
])

AC_OUTPUT

AC_INIT([everarch], [0.1], [markus.peroebner@gmail.com])
AC_CONFIG_SRCDIR([src/evr-glacier-storage.c])
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC
PKG_PROG_PKG_CONFIG

AC_DEFINE(_DEFAULT_SOURCE, 1, This macro can be defined to ensure that the "default" definitions are provided.)
AC_DEFINE(EVR_LOG_DEBUG, , Turns on log message output on level debug)

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

PKG_CHECK_MODULES([GCRYPT], [
    libgcrypt
])

PKG_CHECK_MODULES([EVERARCH], [
    libcjson
    sqlite3
])

AM_PATH_GPGME(1, , AC_MSG_ERROR(GnuPG Made Easy library not found))

PKG_CHECK_MODULES([XML], [libxml-2.0 >= 2.9])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
    Makefile
    src/Makefile
])

AC_OUTPUT

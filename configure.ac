AC_INIT([everarch],[0.1.0],[markus.peroebner@gmail.com])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/evr-glacier-storage.c])
AC_CONFIG_MACRO_DIR([m4])

AC_CHECK_INCLUDES_DEFAULT
AC_PROG_EGREP
AC_PROG_CC

AC_DEFINE([_DEFAULT_SOURCE], [1], [Use modern C features as defined in feature_test_macros(7)])
AC_DEFINE([_XOPEN_SOURCE], [700], [Use modern C features as defined in feature_test_macros(7)])
AC_DEFINE([_POSIX_C_SOURCE], [200809L], [Use modern C features as defined in feature_test_macros(7)])
AC_DEFINE([_GNU_SOURCE], [1], [Use modern linux features with glibc.])

AC_DEFINE(EVR_GCRY_MIN_VERSION, ["1.8.0"], [Minimum version required for libgrcy])

AC_CHECK_HEADER([argp.h], [], AC_MSG_ERROR([Cannot find argparse headers.]))
AC_CHECK_FUNC(
  [argp_parse],
  [have_argp=yes],
  AC_CHECK_LIB([argp],
    [argp_parse],
    [ARGP_LIBS="-largp"],
    []
  )
)
AC_SUBST(ARGP_LIBS)

# the wordexp(…) function is provided via libc by glibc and musl. on
# BSD libc it is an external library. termux provides the wordexp
# library via the package android-wordexp.
AC_CHECK_FUNC(
  [wordexp],
  [have_wordexp=yes],
  AC_CHECK_LIB([android-wordexp],
    [wordexp],
    [WORDEXP_LIBS="-landroid-wordexp"],
    []
  )
)
AC_SUBST(WORDEXP_LIBS)

AC_CHECK_FUNC(
  [backtrace],
  [AC_DEFINE([EVR_HAVE_BACKTRACE], [1], [libc backtrace(…) function is available.])]
)

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

AC_ARG_ENABLE(
  [clang-test-build],
  [AS_HELP_STRING([--enable-clang-test-build], [Enables a clang compatibility test build within a podman container.])],
  [enable_clang_test_build=true],
  [enable_clang_test_build=false]
)
AM_CONDITIONAL([ENABLE_CLANG_TEST_BUILD], [test x$enable_clang_test_build = xtrue])

if test x$prefix = xNONE ; then
  prefix=${ac_default_prefix}
fi

AC_DEFINE_UNQUOTED([EVR_PREFIX], ["${prefix}"], [Path prefix where everarch will be installed])

AC_CHECK_HEADERS([string.h])

AC_FUNC_ALLOCA

AC_CHECK_HEADERS([sys/endian.h])
AC_CHECK_DECLS([be32toh htobe32], [], [],
[AC_INCLUDES_DEFAULT
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif
])

AC_CHECK_FUNCS_ONCE([mkdtemp])

m4_ifndef([PKG_PREREQ],
    [m4_fatal([must install pkg-config 0.29 or later before running autoconf/autogen])])
PKG_PREREQ([0.29.0])
PKG_PROG_PKG_CONFIG([0.9.0])

AX_PTHREAD

m4_ifdef([AM_PATH_LIBGCRYPT],[
    AM_PATH_LIBGCRYPT([1.8.0], , [AC_MSG_ERROR([gcrypt was not found in a sufficient version.])])
  ],
  AC_MSG_ERROR([automake gcrypt support is missing.])
)

AM_PATH_GPGME([1], , AC_MSG_ERROR([GnuPG Made Easy library not found]))

PKG_CHECK_MODULES([SQLITE], [sqlite3])
PKG_CHECK_MODULES([XML], [libxml-2.0 >= 2.9 libxslt >= 1.1])
PKG_CHECK_MODULES([SSL], [libssl >= 1.1 libcrypto >= 1.1])

PKG_CHECK_MODULES([HTTPD], [libmicrohttpd >= 0.9], has_httpd=true, has_httpd=false)
if test "x$has_httpd" == "xtrue"
then
  AC_DEFINE([EVR_HAS_HTTPD], [1], [libmicrohttpd is available.])
fi
AM_CONDITIONAL([HAS_HTTPD], [test x$has_httpd = xtrue])
AC_SUBST(HAS_HTTPD_SUBST, $has_httpd)

AC_PROG_LEX
AC_PROG_YACC
if test "x$LEX" == "x:"
then
  has_lex=false
else
  has_lex=true
fi
AM_CONDITIONAL([HAS_LEX], [test x$has_lex = xtrue])

AM_PATH_PYTHON([3.0], has_python=true, has_python=false)
AM_CONDITIONAL([HAS_PYTHON], [test x$has_python = xtrue])

AC_DEFINE(FUSE_USE_VERSION, [34], [Fuse target API version.])
PKG_CHECK_MODULES([FUSE], [fuse3 >= 3.0], has_fuse=true, has_fuse=false)
AM_CONDITIONAL([HAS_FUSE], [test x$has_fuse = xtrue])
AC_SUBST(HAS_FUSE_SUBST, $has_fuse)

AM_PATH_LISPDIR()
AM_CONDITIONAL([HAS_EMACS], [test x$EMACS != xno])

AC_CHECK_PROG(has_poke, [poke], true, false)
AM_CONDITIONAL([HAS_POKE], [test x$has_poke = xtrue])

AC_CHECK_PROG(has_valgrind, [valgrind], true, false)
AC_SUBST(HAS_VALGRIND, $has_valgrind)

AC_CHECK_PROG(has_podman, [podman], true, false)
AM_CONDITIONAL([HAS_PODMAN], [test x$has_podman = xtrue])

AC_CHECK_PROG(has_xsltproc, [xsltproc], true, false)
AM_CONDITIONAL([TEST_ATTR_SPEC], [test x$has_xsltproc = xtrue])

AC_CHECK_PROG(has_getopt, [getopt], true, false)
AC_CHECK_PROG(has_openssl, [openssl], true, false)
AC_CHECK_PROG(has_openssl, [openssl], true, false)
AC_CHECK_PROG(has_sha224sum, [sha224sum], true, false)

if test x$has_getopt = xtrue -a x$has_openssl = xtrue -a x$has_sha224sum = xtrue
then
  build_evr_backup=true
else
  build_evr_backup=false
fi

AM_CONDITIONAL([BUILD_EVR_BACKUP], $build_evr_backup)
AC_SUBST(BUILD_EVR_BACKUP_SUBST, $build_evr_backup)

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
    Makefile
    test.conf
    src/Makefile
    testing/Makefile
    testing/suite/Makefile
    python/Makefile
    emacs/Makefile
    etc/Makefile
    etc/podman/Makefile
    etc/podman/clang/Makefile
    etc/podman/evr-alpine/Makefile
    etc/podman/evr-glacier-storage/Makefile
    etc/podman/evr-attr-index/Makefile
    etc/podman/evr-join-link/Makefile
    etc/podman/evr-upload-httpd/Makefile
    etc/podman/evr-web/Makefile
    etc/podman/evr-websocket-server/Makefile
    etc/poke-pickles/Makefile
    testing/suite/config
])

AC_OUTPUT

AC_MSG_NOTICE([With the results from the checks above configure decided the following.
	build evr-attr-index: $has_lex
	build evr-backup: $build_evr_backup
        build fuse file systems: $has_fuse
        http server for evr-attr-index: $has_httpd
        test clang build: $enable_clang_test_build
        test evr-attr-index default attr-spec transformations: $has_xsltproc
])

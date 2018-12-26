AC_PREREQ(2.61)
AC_INIT(yk-secret-tool, 0.1, ondrej.holecek@gmail.com)
AC_CONFIG_SRCDIR([src/yk-secret-tool.c])
m4_ifdef([AM_SILENT_RULES],
  [AM_SILENT_RULES([yes])],
  [AC_SUBST([AM_DEFAULT_VERBOSITY], [1])])
AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_MAINTAINER_MODE([enable])
LT_INIT

PKG_PROG_PKG_CONFIG
AC_PROG_CC
AC_PROG_CC_STDC
AC_LANG_WERROR


PKG_CHECK_MODULES([YKPIV], [ ykpiv >= 1.6 ])

AC_CHECK_LIB(crypto, CRYPTO_new_ex_data, [
	TCPLAY_DEPS_LIBS+=' -lcrypto'
	CRYPTO_LIBS=crypto
	AC_SUBST([CRYPTO_LIBS])
], [AC_MSG_ERROR([library 'crypto' is required])])

AC_CONFIG_HEADER(config.h)
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

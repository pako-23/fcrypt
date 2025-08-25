AC_PREREQ([2.71])
AC_INIT([fcrypt], [0.0.1])
AC_CONFIG_MACRO_DIR([m4])

AX_NO_INSOURCE

AM_INIT_AUTOMAKE([-Wall -Werror gnu subdir-objects])
AM_SILENT_RULES([yes])

AC_PROG_CC
AM_PROG_AR
AC_PROG_SED

AC_CHECK_FUNCS([dup2 memmove memset])
AC_CHECK_HEADERS([stdint.h unistd.h])
AC_CHECK_LIB([pthread], [pthread_create])
AC_C_INLINE
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_PROG_INSTALL
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT64_T


AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug], [enable debugging, default: no])],
  [
    CFLAGS="$(echo "$CFLAGS" | $SED -e 's/-O[0-9]*//g' -e 's/-g[0-9]*//g') -g3 -O0  -fno-omit-frame-pointer"

    AC_CHECK_LIB([gcov], [__gcov_init],
      [
        CODE_COVERAGE_CFLAGS="-fprofile-arcs -ftest-coverage"
        CODE_COVERAGE_LIBS="-lgcov"
      ],
      [
        CODE_COVERAGE_CFLAGS=""
        CODE_COVERAGE_LIBS=""
      ])

    AC_CHECK_PROG([LCOV], [lcov], [lcov])
    AS_IF([test x"$LCOV" = x], [
	  AC_MSG_WARN([To enable code coverage reporting you must have lcov installed])
	])

    AC_CHECK_PROG([GENHTML], [genhtml], [genhtml])
	AS_IF([test x"$GENHTML" = x], [
	  AC_MSG_WARN([Could not find genhtml from the lcov package])
	])

	AC_SUBST([CODE_COVERAGE_CFLAGS])
	AC_SUBST([CODE_COVERAGE_LIBS])
    AM_CONDITIONAL([HAVE_COVERAGE_REPORT],
      [test x"$CODE_COVERAGE_LIBS" != x && test x"$LCOV" != x && test x"$GENHTML" != x])
  ],[AM_CONDITIONAL([HAVE_COVERAGE_REPORT],[0])])

AX_VALGRIND_CHECK

LT_INIT

AX_FIND_INDENT

AC_CONFIG_FILES([
  Makefile
  src/Makefile
  src/crypt/Makefile
])

PKG_CHECK_MODULES([CHECK], [check >= 0.15.0], [
  AC_CONFIG_FILES([
    tests/Makefile
  ])
  AC_SUBST([CHECK_CFLAGS])
  AC_SUBST([CHECK_LIBS])
])

AC_OUTPUT

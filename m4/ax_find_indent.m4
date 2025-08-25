AC_DEFUN([AX_FIND_INDENT],[
  AC_CHECK_PROGS([INDENT], [indent], [no])
  AS_IF([test "$INDENT" = "no"], [
    AC_MSG_NOTICE([indent is not installed.])
  ])

  AM_CONDITIONAL([HAVE_INDENT], [test "$INDENT" != "no"])
])

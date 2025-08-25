AC_DEFUN([AX_NO_INSOURCE],[
   AS_IF([test "$srcdir" == "."],
     [AC_MSG_ERROR([In-source builds are not allowed. Instead build into a different directory.])
   ])
])

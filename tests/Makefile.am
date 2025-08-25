TESTS = check_randgen
check_PROGRAMS = check_randgen

check_randgen_SOURCES = crypt/check_randgen.c
check_randgen_CFLAGS = $(CHECK_CFLAGS) -I$(top_srcdir)/src/crypt/include
check_randgen_LDADD = $(top_builddir)/src/crypt/libcrypt.la $(CHECK_LIBS)

@VALGRIND_CHECK_RULES@

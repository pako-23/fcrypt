TESTS = check_randgen check_otp check_rc4
check_PROGRAMS = check_randgen check_otp check_rc4

check_randgen_SOURCES = crypt/check_randgen.c
check_randgen_CFLAGS = $(CHECK_CFLAGS) -I$(top_srcdir)/src/crypt/include
check_randgen_LDADD = $(top_builddir)/src/crypt/libcrypt.la $(CHECK_LIBS)

check_otp_SOURCES = crypt/check_otp.c
check_otp_CFLAGS = $(CHECK_CFLAGS) -I$(top_srcdir)/src/crypt/include
check_otp_LDADD = $(top_builddir)/src/crypt/libcrypt.la $(CHECK_LIBS)

check_rc4_SOURCES = crypt/check_rc4.c
check_rc4_CFLAGS = $(CHECK_CFLAGS) -I$(top_srcdir)/src/crypt/include
check_rc4_LDADD = $(top_builddir)/src/crypt/libcrypt.la $(CHECK_LIBS)

@VALGRIND_CHECK_RULES@

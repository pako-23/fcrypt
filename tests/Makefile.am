TESTS = check_cbc \
	check_cfb \
	check_des \
	check_ecb \
	check_fcrypt \
	check_ofb \
	check_otp \
	check_randgen \
	check_rc4 \
	check_tdea
check_PROGRAMS = check_cbc \
	check_cfb \
	check_des \
	check_ecb \
	check_fcrypt \
	check_ofb \
	check_otp \
	check_randgen \
	check_rc4 \
	check_tdea

check_cbc_SOURCES = crypt/check_cbc.c
check_cbc_CFLAGS = $(CHECK_CFLAGS) -I$(top_srcdir)/src/crypt/include
check_cbc_LDADD = $(top_builddir)/src/crypt/libcrypt.la $(CHECK_LIBS)

check_cfb_SOURCES = crypt/check_cfb.c
check_cfb_CFLAGS = $(CHECK_CFLAGS) -I$(top_srcdir)/src/crypt/include
check_cfb_LDADD = $(top_builddir)/src/crypt/libcrypt.la $(CHECK_LIBS)

check_des_SOURCES = crypt/check_des.c
check_des_CFLAGS = $(CHECK_CFLAGS) -I$(top_srcdir)/src/crypt/include
check_des_LDADD = $(top_builddir)/src/crypt/libcrypt.la $(CHECK_LIBS)

check_ecb_SOURCES = crypt/check_ecb.c
check_ecb_CFLAGS = $(CHECK_CFLAGS) -I$(top_srcdir)/src/crypt/include
check_ecb_LDADD = $(top_builddir)/src/crypt/libcrypt.la $(CHECK_LIBS)

check_fcrypt_SOURCES = check_fcrypt.c
check_fcrypt_CFLAGS = $(CHECK_CFLAGS) \
	-I$(top_srcdir)/src/include \
	-I$(top_srcdir)/src/crypt/include
check_fcrypt_LDADD = $(top_builddir)/src/libfcrypt.la \
	$(top_builddir)/src/crypt/libcrypt.la \
	$(CHECK_LIBS)

check_ofb_SOURCES = crypt/check_ofb.c
check_ofb_CFLAGS = $(CHECK_CFLAGS) -I$(top_srcdir)/src/crypt/include
check_ofb_LDADD = $(top_builddir)/src/crypt/libcrypt.la $(CHECK_LIBS)

check_otp_SOURCES = crypt/check_otp.c
check_otp_CFLAGS = $(CHECK_CFLAGS) -I$(top_srcdir)/src/crypt/include
check_otp_LDADD = $(top_builddir)/src/crypt/libcrypt.la $(CHECK_LIBS)

check_randgen_SOURCES = crypt/check_randgen.c
check_randgen_CFLAGS = $(CHECK_CFLAGS) -I$(top_srcdir)/src/crypt/include
check_randgen_LDADD = $(top_builddir)/src/crypt/libcrypt.la $(CHECK_LIBS)

check_rc4_SOURCES = crypt/check_rc4.c
check_rc4_CFLAGS = $(CHECK_CFLAGS) -I$(top_srcdir)/src/crypt/include
check_rc4_LDADD = $(top_builddir)/src/crypt/libcrypt.la $(CHECK_LIBS)

check_tdea_SOURCES = crypt/check_tdea.c
check_tdea_CFLAGS = $(CHECK_CFLAGS) -I$(top_srcdir)/src/crypt/include
check_tdea_LDADD = $(top_builddir)/src/crypt/libcrypt.la $(CHECK_LIBS)

@VALGRIND_CHECK_RULES@

SUBDIRS = crypt

bin_PROGRAMS = fcrypt
lib_LTLIBRARIES = libfcrypt.la

libfcrypt_la_SOURCES = fcrypt.c
libfcrypt_la_CFLAGS = -I$(abs_srcdir)/include \
	-I$(abs_srcdir)/crypt/include \
	$(CODE_COVERAGE_CFLAGS) -fPIC
libfcrypt_la_LIBADD = $(top_builddir)/src/crypt/libcrypt.la
libfcrypt_la_LDFLAGS = -version-info 0:0:0 \
	-no-undefined \
	-module -static $(CODE_COVERAGE_LIBS)

fcrypt_SOURCES = main.c
fcrypt_CFLAGS = -I$(abs_srcdir)/include
fcrypt_LDADD = $(builddir)/libfcrypt.la $(top_builddir)/src/crypt/libcrypt.la

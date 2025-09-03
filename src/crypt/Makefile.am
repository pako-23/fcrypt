lib_LTLIBRARIES = libcrypt.la

libcrypt_la_SOURCES = block.c \
	des.c \
	rand.c \
	stream.c \
	include/crypt/block.h \
	include/crypt/des.h \
	include/crypt/rand.h \
	include/crypt/stream.h
libcrypt_la_CFLAGS = -I$(abs_srcdir)/include $(CODE_COVERAGE_CFLAGS) -fPIC
libcrypt_la_LDFLAGS = -version-info 0:0:0 \
	-no-undefined \
	-module -static $(CODE_COVERAGE_LIBS)

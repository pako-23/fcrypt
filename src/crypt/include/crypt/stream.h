#ifndef CRYPT_STREAM_H_INCLUDED
#define CRYPT_STREAM_H_INCLUDED

#include <stddef.h>

void cr_otp(const unsigned char *plain, const unsigned char *key,
	    unsigned char *out, size_t len);

#endif

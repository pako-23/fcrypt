#include <crypt/stream.h>
#include <stddef.h>

void cr_otp(const unsigned char *plain, const unsigned char *key,
	    unsigned char *out, size_t len)
{
	for (size_t i = 0; i < len; ++i)
		*out++ = *plain++ ^ *key++;
}

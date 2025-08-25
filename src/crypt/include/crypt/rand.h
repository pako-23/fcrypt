#ifndef CRYPT_RAND_H_INCLUDED
#define CRYPT_RAND_H_INCLUDED

#include <stddef.h>

int cr_rand_bytes(unsigned char *buf, size_t len);

#endif

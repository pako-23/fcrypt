#ifndef CRYPT_STREAM_H_INCLUDED
#define CRYPT_STREAM_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

struct cr_rc4_s;

void cr_otp(const unsigned char *in, const unsigned char *key,
	    unsigned char *out, size_t len);

struct cr_rc4_s *cr_rc4_new(const uint8_t * key, size_t len);
void cr_rc4_destroy(struct cr_rc4_s *cipher);

int cr_rc4_encrypt(struct cr_rc4_s *cipher, const uint8_t * plain, size_t len,
		   uint8_t * out);
int cr_rc4_decrypt(struct cr_rc4_s *cipher, const uint8_t * ctext, size_t len,
		   uint8_t * out);

#endif

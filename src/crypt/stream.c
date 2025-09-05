#include <crypt/stream.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

struct cr_rc4_s {
	int i;
	int j;
	uint8_t S[256];
};

void cr_otp(const unsigned char *in, const unsigned char *key,
	    unsigned char *out, size_t len)
{
	size_t i;

	for (i = 0; i < len; ++i)
		*out++ = *in++ ^ *key++;
}

struct cr_rc4_s *cr_rc4_new(const uint8_t *key, size_t len)
{
	struct cr_rc4_s *cipher;
	int j, i;
	uint8_t tmp;

	cipher = malloc(sizeof(struct cr_rc4_s));
	if (cipher == NULL)
		return NULL;

	cipher->i = cipher->j = 0;
	for (i = 0; i < 256; ++i)
		cipher->S[i] = i;

	for (i = 0, j = 0; i < 256; ++i) {
		j = (j + cipher->S[i] + key[i % len]) % 256;

		tmp = cipher->S[i];
		cipher->S[i] = cipher->S[j];
		cipher->S[j] = tmp;
	}

	return cipher;
}

void cr_rc4_destroy(struct cr_rc4_s *cipher)
{
	free(cipher);
}

static uint8_t cr_rc4_byte(struct cr_rc4_s *cipher)
{
	uint8_t t;

	cipher->i = (cipher->i + 1) % 256;
	cipher->j = (cipher->j + cipher->S[cipher->i]) % 256;

	t = cipher->S[cipher->i];
	cipher->S[cipher->i] = cipher->S[cipher->j];
	cipher->S[cipher->j] = t;

	t = (cipher->S[cipher->i] + cipher->S[cipher->j]) % 256;
	return cipher->S[t];

}

static int cr_rc4_stream(struct cr_rc4_s *cipher, const uint8_t *plain,
			 size_t len, uint8_t *out)
{
	size_t i;

	for (i = 0; i < len; ++i)
		*out++ = *plain++ ^ cr_rc4_byte(cipher);

	return 0;
}

int cr_rc4_encrypt(struct cr_rc4_s *cipher, const uint8_t *plain, size_t len,
		   uint8_t *out)
{
	return cr_rc4_stream(cipher, plain, len, out);
}

int cr_rc4_decrypt(struct cr_rc4_s *cipher, const uint8_t *ctext, size_t len,
		   uint8_t *out)
{
	return cr_rc4_stream(cipher, ctext, len, out);
}

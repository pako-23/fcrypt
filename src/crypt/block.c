#include "crypt/des.h"
#include <crypt/block.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct cr_bcphr_s {
	blkencrypt_t encrypt;
	blkdecrypt_t decrypt;
	enum cr_bcphr_mode mode;
	size_t blksz;
	size_t keysz;
	size_t written;
	uint8_t *block;
	uint8_t *iv;
	uint8_t *key;
};

static size_t ecb_encrypt(struct cr_bcphr_s *cipher, const uint8_t * plain,
			  size_t len, uint8_t * out);
static size_t ecb_decrypt(struct cr_bcphr_s *cipher, const uint8_t * plain,
			  size_t len, uint8_t * out);

static size_t (*encypt_modes[])(struct cr_bcphr_s *, const uint8_t *, size_t,
				uint8_t *) = {
	ecb_encrypt,
};

static size_t (*decrypt_modes[])(struct cr_bcphr_s *, const uint8_t *, size_t,
				 uint8_t *) = {
	ecb_decrypt,
};

struct cr_bcphr_s *cr_bcphr_new(const uint8_t *key,
				size_t keysz,
				size_t blksz,
				blkencrypt_t encrypt,
				blkdecrypt_t decrypt, enum cr_bcphr_mode mode)
{
	struct cr_bcphr_s *cipher;

	cipher = malloc(sizeof(struct cr_bcphr_s));
	if (cipher == NULL)
		goto out;

	cipher->block = malloc(blksz);
	if (cipher->block == NULL)
		goto cipher_clean;

	cipher->iv = malloc(blksz);
	if (cipher->iv == NULL)
		goto block_clean;

	cipher->key = malloc(keysz);
	if (cipher->key == NULL)
		goto iv_clean;

	cipher->encrypt = encrypt;
	cipher->decrypt = decrypt;
	cipher->mode = mode;
	cipher->blksz = blksz;
	cipher->keysz = keysz;
	cipher->written = 0;
	memset(cipher->iv, 0, blksz);
	memcpy(cipher->key, key, keysz);

	return cipher;

 iv_clean:
	free(cipher->iv);
 block_clean:
	free(cipher->block);
 cipher_clean:
	free(cipher);
 out:
	return NULL;
}

void cr_bcphr_destroy(struct cr_bcphr_s *cipher)
{
	free(cipher->block);
	free(cipher->iv);
	free(cipher->key);
	free(cipher);
}

size_t cr_bcphr_block_size(const struct cr_bcphr_s *cipher)
{
	return cipher->blksz;
}

void cr_bcphr_set_iv(struct cr_bcphr_s *cipher, const uint8_t *iv)
{
	if (cipher->mode == CR_BCPHR_ECB_MODE)
		return;
	memcpy(cipher->iv, iv, cr_bcphr_block_size(cipher));
}

size_t cr_bcphr_encrypt(struct cr_bcphr_s *cipher, const uint8_t *plain,
			size_t len, uint8_t *out)
{
	return encypt_modes[cipher->mode] (cipher, plain, len, out);
}

size_t cr_bcphr_decrypt(struct cr_bcphr_s *cipher, const uint8_t *ctext,
			size_t len, uint8_t *out)
{
	return decrypt_modes[cipher->mode] (cipher, ctext, len, out);
}

void cr_bcphr_encrypt_finalize(struct cr_bcphr_s *cipher, uint8_t *out)
{
	size_t blksz = cr_bcphr_block_size(cipher);
	uint8_t pad = blksz - cipher->written;

	while (cipher->written < blksz)
		cipher->block[cipher->written++] = pad;

	// TODO this is completely wrong since it does not use the iv yet

	cipher->encrypt(cipher->block, cipher->key, out);
}

ssize_t cr_bcphr_decrypt_finalize(struct cr_bcphr_s *cipher, uint8_t *out)
{
	size_t blksz = cr_bcphr_block_size(cipher);

	if (cipher->written != blksz)
		return -1;

	cipher->decrypt(cipher->block, cipher->key, out);
	// TODO this is completely wrong since it does not use the iv yet

	return blksz - out[blksz - 1];
}

static size_t ecb_encrypt(struct cr_bcphr_s *cipher, const uint8_t *plain,
			  size_t len, uint8_t *out)
{
	size_t blksz = cr_bcphr_block_size(cipher);
	size_t blocks = (cipher->written + len) / blksz;

	if (out == NULL)
		return blocks * blksz;

	for (size_t i = 0; i < blocks; ++i) {
		size_t left = blksz - cipher->written;
		memcpy(cipher->block + cipher->written, plain, left);

		cipher->encrypt(cipher->block, cipher->key, out);
		cipher->written = 0;
		out += blksz;
		len -= left;
		plain += left;
	}

	memcpy(cipher->block, plain, len);
	cipher->written = len;

	return blocks * blksz;
}

static size_t ecb_decrypt(struct cr_bcphr_s *cipher, const uint8_t *plain,
			  size_t len, uint8_t *out)
{
	size_t blksz = cr_bcphr_block_size(cipher);
	size_t blocks = (cipher->written + len) / blksz;

	if (blocks * blksz == len)
		blocks -= 1;
	if (out == NULL)
		return blocks * blksz;

	for (size_t i = 0; i < blocks; ++i) {
		size_t left = blksz - cipher->written;
		memcpy(cipher->block + cipher->written, plain, left);

		cipher->decrypt(cipher->block, cipher->key, out);
		cipher->written = 0;

		out += blksz;
		len -= left;
		plain += left;
	}

	cipher->written = len;
	memcpy(cipher->block, plain, len);

	return blocks * blksz;
}

struct cr_bcphr_s *cr_bcphr_des(const uint8_t *key, enum cr_bcphr_mode mode)
{
	return cr_bcphr_new(key, 8, 8, cr_des_encrypt, cr_des_decrypt, mode);
}

struct cr_bcphr_s *cr_bcphr_tdea(const uint8_t *key, enum cr_bcphr_mode mode)
{
	return cr_bcphr_new(key, 24, 8, cr_tdea_encrypt, cr_tdea_decrypt, mode);
}

#include <crypt/des.h>
#include <crypt/rand.h>
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

static void ecb_encrypt(struct cr_bcphr_s *cipher, uint8_t * out);
static void ecb_decrypt(struct cr_bcphr_s *cipher, uint8_t * out);

static void cbc_encrypt(struct cr_bcphr_s *cipher, uint8_t * out);
static void cbc_decrypt(struct cr_bcphr_s *cipher, uint8_t * out);

static void cfb_encrypt(struct cr_bcphr_s *cipher, uint8_t * out);
static void cfb_decrypt(struct cr_bcphr_s *cipher, uint8_t * out);

static void ofb_encrypt(struct cr_bcphr_s *cipher, uint8_t * out);
static void ofb_decrypt(struct cr_bcphr_s *cipher, uint8_t * out);

static void (*encypt_modes[])(struct cr_bcphr_s *, uint8_t *) = {
	ecb_encrypt, cbc_encrypt, cfb_encrypt,
	ofb_encrypt,
};

static void (*decrypt_modes[])(struct cr_bcphr_s *, uint8_t *) = {
	ecb_decrypt, cbc_decrypt, cfb_decrypt,
	ofb_decrypt,
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

	if (cr_rand_bytes(cipher->iv, blksz) != 0)
		goto iv_clean;

	cipher->key = malloc(keysz);
	if (cipher->key == NULL)
		goto iv_clean;

	cipher->encrypt = encrypt;
	cipher->decrypt = decrypt;
	cipher->mode = mode;
	cipher->blksz = blksz;
	cipher->keysz = keysz;
	cipher->written = 0;
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
	memcpy(cipher->iv, iv, cr_bcphr_block_size(cipher));
}

size_t cr_bcphr_get_iv(const struct cr_bcphr_s *cipher, uint8_t *iv)
{
	size_t blksz = cr_bcphr_block_size(cipher);

	memcpy(iv, cipher->iv, blksz);
	return blksz;
}

enum cr_bcphr_mode cr_bcphr_get_mode(const struct cr_bcphr_s *cipher)
{
	return cipher->mode;
}

size_t cr_bcphr_encrypt(struct cr_bcphr_s *cipher, const uint8_t *plain,
			size_t len, uint8_t *out)
{
	size_t blksz = cr_bcphr_block_size(cipher);
	size_t blocks = (cipher->written + len) / blksz;

	if (out == NULL)
		return blocks * blksz;

	for (size_t i = 0; i < blocks; ++i) {
		size_t left = blksz - cipher->written;
		memcpy(cipher->block + cipher->written, plain, left);

		encypt_modes[cipher->mode] (cipher, out);

		cipher->written = 0;
		out += blksz;
		len -= left;
		plain += left;
	}

	memcpy(cipher->block, plain, len);
	cipher->written = len;

	return blocks * blksz;
}

size_t cr_bcphr_decrypt(struct cr_bcphr_s *cipher, const uint8_t *ctext,
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
		memcpy(cipher->block + cipher->written, ctext, left);

		decrypt_modes[cipher->mode] (cipher, out);
		cipher->written = 0;

		out += blksz;
		len -= left;
		ctext += left;
	}

	cipher->written = len;
	memcpy(cipher->block, ctext, len);

	return blocks * blksz;
}

void cr_bcphr_encrypt_finalize(struct cr_bcphr_s *cipher, uint8_t *out)
{
	size_t blksz = cr_bcphr_block_size(cipher);
	uint8_t pad = blksz - cipher->written;

	while (cipher->written < blksz)
		cipher->block[cipher->written++] = pad;

	encypt_modes[cipher->mode] (cipher, out);
}

ssize_t cr_bcphr_decrypt_finalize(struct cr_bcphr_s *cipher, uint8_t *out)
{
	size_t blksz = cr_bcphr_block_size(cipher);
	uint8_t pad;

	if (cipher->written != blksz)
		return -1;

	decrypt_modes[cipher->mode] (cipher, out);
	pad = out[blksz - 1];
	if (pad > blksz)
		return -1;

	for (uint8_t i = 0; i < pad; ++i)
		if (out[blksz - 1 - i] != pad)
			return -1;

	return blksz - out[blksz - 1];
}

struct cr_bcphr_s *cr_bcphr_des(const uint8_t *key, enum cr_bcphr_mode mode)
{
	return cr_bcphr_new(key, des_keysz, des_blksz, cr_des_encrypt,
			    cr_des_decrypt, mode);
}

struct cr_bcphr_s *cr_bcphr_tdea(const uint8_t *key, enum cr_bcphr_mode mode)
{
	return cr_bcphr_new(key, tdea_keysz, tdea_blksz, cr_tdea_encrypt,
			    cr_tdea_decrypt, mode);
}

static void ecb_encrypt(struct cr_bcphr_s *cipher, uint8_t *out)
{
	cipher->encrypt(cipher->block, cipher->key, out);
}

static void ecb_decrypt(struct cr_bcphr_s *cipher, uint8_t *out)
{
	cipher->decrypt(cipher->block, cipher->key, out);
}

static void cbc_encrypt(struct cr_bcphr_s *cipher, uint8_t *out)
{
	size_t blksz = cr_bcphr_block_size(cipher);

	for (size_t j = 0; j < blksz; ++j)
		cipher->block[j] ^= cipher->iv[j];

	cipher->encrypt(cipher->block, cipher->key, out);
	memcpy(cipher->iv, out, blksz);
}

static void cbc_decrypt(struct cr_bcphr_s *cipher, uint8_t *out)
{
	size_t blksz = cr_bcphr_block_size(cipher);

	cipher->decrypt(cipher->block, cipher->key, out);

	for (size_t j = 0; j < blksz; ++j)
		out[j] ^= cipher->iv[j];

	memcpy(cipher->iv, cipher->block, blksz);
}

static void cfb_encrypt(struct cr_bcphr_s *cipher, uint8_t *out)
{
	size_t blksz = cr_bcphr_block_size(cipher);

	cipher->encrypt(cipher->iv, cipher->key, out);
	for (size_t i = 0; i < blksz; ++i)
		out[i] ^= cipher->block[i];

	memcpy(cipher->iv, out, blksz);
}

static void cfb_decrypt(struct cr_bcphr_s *cipher, uint8_t *out)
{
	size_t blksz = cr_bcphr_block_size(cipher);

	cipher->encrypt(cipher->iv, cipher->key, out);
	memcpy(cipher->iv, cipher->block, blksz);
	for (size_t i = 0; i < blksz; ++i)
		out[i] ^= cipher->block[i];
}

static void ofb_encrypt(struct cr_bcphr_s *cipher, uint8_t *out)
{
	size_t blksz = cr_bcphr_block_size(cipher);

	cipher->encrypt(cipher->iv, cipher->key, out);
	memcpy(cipher->iv, out, blksz);

	for (size_t i = 0; i < blksz; ++i)
		out[i] ^= cipher->block[i];
}

static void ofb_decrypt(struct cr_bcphr_s *cipher, uint8_t *out)
{
	size_t blksz = cr_bcphr_block_size(cipher);

	cipher->encrypt(cipher->iv, cipher->key, out);
	memcpy(cipher->iv, out, blksz);
	for (size_t i = 0; i < blksz; ++i)
		out[i] ^= cipher->block[i];
}

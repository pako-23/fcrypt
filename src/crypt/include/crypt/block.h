#ifndef CRYPT_BLOCK_H_INCLUDED
#define CRYPT_BLOCK_H_INCLUDED

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

enum cr_bcphr_mode {
	CR_BCPHR_ECB_MODE = 0x00,
	CR_BCPHR_CBC_MODE = 0x01,
	CR_BCPHR_CFB_MODE = 0x02,
	CR_BCPHR_OFB_MODE = 0x03,
};

struct cr_bcphr_s;

typedef void (*blkencrypt_t)(const uint8_t * plain, const uint8_t * key,
			     uint8_t * out);
typedef void (*blkdecrypt_t)(const uint8_t * ctext, const uint8_t * key,
			     uint8_t * out);

struct cr_bcphr_s *cr_bcphr_new(const uint8_t * key,
				size_t keysz,
				size_t blksz,
				blkencrypt_t encrypt,
				blkdecrypt_t decrypt, enum cr_bcphr_mode mode);
void cr_bcphr_destroy(struct cr_bcphr_s *cipher);

size_t cr_bcphr_block_size(const struct cr_bcphr_s *cipher);
void cr_bcphr_set_iv(struct cr_bcphr_s *cipher, const uint8_t * iv);
size_t cr_bcphr_get_iv(const struct cr_bcphr_s *cipher, uint8_t * iv);
enum cr_bcphr_mode cr_bcphr_get_mode(const struct cr_bcphr_s *cipher);

size_t cr_bcphr_encrypt(struct cr_bcphr_s *cipher, const uint8_t * plain,
			size_t len, uint8_t * out);
void cr_bcphr_encrypt_finalize(struct cr_bcphr_s *cipher, uint8_t * out);

size_t cr_bcphr_decrypt(struct cr_bcphr_s *cipher, const uint8_t * ctext,
			size_t len, uint8_t * out);
ssize_t cr_bcphr_decrypt_finalize(struct cr_bcphr_s *cipher, uint8_t * out);

struct cr_bcphr_s *cr_bcphr_des(const uint8_t * key, enum cr_bcphr_mode mode);
struct cr_bcphr_s *cr_bcphr_tdea(const uint8_t * key, enum cr_bcphr_mode mode);

#endif

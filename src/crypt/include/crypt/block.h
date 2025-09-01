#ifndef CRYPT_BLOCK_H_INCLUDED
#define CRYPT_BLOCK_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

struct cr_bcphr_s;

struct cr_bcphr_ops_s {
	size_t (*blkencrypt)(struct cr_bcphr_s *, uint8_t *);
	size_t (*blkdecrypt)(struct cr_bcphr_s *, uint8_t *);
};

struct cr_bcphr_s {
	const struct cr_bcphr_ops_s ops;
	int blksz;
};

int cr_bcphr_block_size(struct cr_bcphr_s *cipher);
int cr_bcphr_blkencrypt(struct cr_bcphr_s *cipher, uint8_t *);
int cr_bcphr_blkdecrypt(struct cr_bcphr_s *cipher, uint8_t *);

#endif

#ifndef CRYPT_DES_H_INCLUDED
#define CRYPT_DES_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

void cr_des_encrypt(const uint8_t *plain, const uint8_t *key, uint8_t *out);
void cr_des_decrypt(const uint8_t *ctext, const uint8_t *key, uint8_t *out);

void cr_tdea_encrypt(uint8_t *plain, uint8_t *key, uint8_t *out);
void cr_tdea_decrypt(uint8_t *ctext, uint8_t *key, uint8_t *out);

#endif

#ifndef CRYPT_DES_H_INCLUDED
#define CRYPT_DES_H_INCLUDED

#include <stddef.h>
#include <stdint.h>

extern const size_t des_blksz;
extern const size_t tdea_blksz;
extern const size_t des_keysz;
extern const size_t tdea_keysz;

void cr_des_encrypt(const uint8_t * plain, const uint8_t * key, uint8_t * out);
void cr_des_decrypt(const uint8_t * ctext, const uint8_t * key, uint8_t * out);

void cr_tdea_encrypt(const uint8_t * plain, const uint8_t * key, uint8_t * out);
void cr_tdea_decrypt(const uint8_t * ctext, const uint8_t * key, uint8_t * out);

#endif

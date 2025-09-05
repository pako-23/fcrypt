#include <check.h>
#include <crypt/des.h>
#include <crypt/rand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

START_TEST(constants)
{
	ck_assert_int_eq(des_blksz, 8);
	ck_assert_int_eq(des_keysz, 8);
}

END_TEST START_TEST(encryption_1)
{
	const uint8_t key[] =
	    { 0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59 };
	const uint8_t plaintext[] =
	    { 02, 0x46, 0x8a, 0xce, 0xec, 0xa8, 0x64, 0x20 };
	const uint8_t expected[] =
	    { 0xda, 0x02, 0xce, 0x3a, 0x89, 0xec, 0xac, 0x3b };
	uint8_t ciphertext[8];

	cr_des_encrypt(plaintext, key, ciphertext);
	ck_assert_mem_eq(ciphertext, expected, 8);
}

END_TEST START_TEST(encryption_2)
{
	const uint8_t key[] = { 0xbb, 0x4f, 0xf, 0xd9, 0xdc, 0xf1, 0xb3, 0xb9 };
	const uint8_t plaintext[] =
	    { 0xac, 0xf, 0xf5, 0x0, 0xb1, 0x95, 0xf4, 0x83 };
	const uint8_t expected[] =
	    { 0xff, 0xf3, 0x47, 0xa4, 0x53, 0x9c, 0x7, 0x30 };
	uint8_t ciphertext[8];

	cr_des_encrypt(plaintext, key, ciphertext);
	ck_assert_mem_eq(ciphertext, expected, 8);
}

END_TEST START_TEST(encryption_3)
{
	const uint8_t key[] = { 0x6e, 0xe5, 0x0, 0x91, 0xa4, 0xd3, 0x13, 0x36 };
	const uint8_t plaintext[] =
	    { 0xb9, 0xd4, 0xcc, 0x3, 0xe9, 0x68, 0x62, 0x6c };
	const uint8_t expected[] =
	    { 0xdd, 0x24, 0x8b, 0x5e, 0xf6, 0x12, 0xc2, 0xeb };
	uint8_t ciphertext[8];

	cr_des_encrypt(plaintext, key, ciphertext);
	ck_assert_mem_eq(ciphertext, expected, 8);
}

END_TEST START_TEST(encryption_4)
{
	const uint8_t key[] =
	    { 0x95, 0x76, 0x9f, 0xdd, 0x8f, 0xdf, 0x90, 0xa9 };
	const uint8_t plaintext[] =
	    { 0x39, 0x29, 0xcc, 0x41, 0xcf, 0x42, 0x4b, 0x27 };
	const uint8_t expected[] =
	    { 0x7c, 0xf5, 0x45, 0x60, 0x71, 0x36, 0x82, 0xa5 };
	uint8_t ciphertext[8];

	cr_des_encrypt(plaintext, key, ciphertext);
	ck_assert_mem_eq(ciphertext, expected, 8);
}

END_TEST START_TEST(encryption_5)
{
	const uint8_t key[] = { 0xaa, 0x58, 0x6, 0x1c, 0x9e, 0xb, 0x11, 0xc6 };
	const uint8_t plaintext[] =
	    { 0xbe, 0x4b, 0x2a, 0xe7, 0xd2, 0xa3, 0xde, 0xb5 };
	const uint8_t expected[] =
	    { 0x8e, 0x84, 0x50, 0xc3, 0x79, 0x54, 0xe5, 0x78 };
	uint8_t ciphertext[8];

	cr_des_encrypt(plaintext, key, ciphertext);
	ck_assert_mem_eq(ciphertext, expected, 8);
}

END_TEST START_TEST(encryption_6)
{
	const uint8_t key[] = { 0x80, 0x94, 0x1, 0xd2, 0xaf, 0xd4, 0x55, 0xb7 };
	const uint8_t plaintext[] =
	    { 0x3e, 0x26, 0x72, 0xa8, 0xec, 0x7c, 0x5, 0xf5 };
	const uint8_t expected[] =
	    { 0xe3, 0xa0, 0x88, 0x5d, 0x9e, 0xf7, 0x64, 0x3b };
	uint8_t ciphertext[8];

	cr_des_encrypt(plaintext, key, ciphertext);
	ck_assert_mem_eq(ciphertext, expected, 8);
}

END_TEST START_TEST(encryption_7)
{
	const uint8_t key[] =
	    { 0x78, 0x3a, 0xe1, 0x61, 0xca, 0x17, 0x3e, 0xae };
	const uint8_t plaintext[] =
	    { 0xc0, 0xc8, 0x9f, 0x4e, 0x76, 0xf9, 0xdc, 0xad };
	const uint8_t expected[] =
	    { 0x8d, 0x40, 0x6a, 0x7e, 0xe3, 0x44, 0x61, 0xd4 };
	uint8_t ciphertext[8];

	cr_des_encrypt(plaintext, key, ciphertext);
	ck_assert_mem_eq(ciphertext, expected, 8);
}

END_TEST START_TEST(encryption_8)
{
	const uint8_t key[] = { 0x9, 0x15, 0x6e, 0xc0, 0x92, 0x14, 0xe8, 0xf4 };
	const uint8_t plaintext[] =
	    { 0xe, 0x18, 0x38, 0xec, 0xc5, 0x22, 0x9a, 0x1 };
	const uint8_t expected[] =
	    { 0xbd, 0x81, 0x9e, 0x2b, 0xed, 0xa4, 0xa0, 0xc1 };
	uint8_t ciphertext[8];

	cr_des_encrypt(plaintext, key, ciphertext);
	ck_assert_mem_eq(ciphertext, expected, 8);
}

END_TEST START_TEST(encryption_9)
{
	const uint8_t key[] = { 0xd9, 0x7c, 0x7f, 0x8a, 0x19, 0x54, 0x8, 0x9 };
	const uint8_t plaintext[] =
	    { 0xee, 0x3f, 0x71, 0x7e, 0xe4, 0x8e, 0x4d, 0xc9 };
	const uint8_t expected[] =
	    { 0x70, 0xb7, 0x9a, 0x1f, 0x5f, 0xb2, 0x53, 0x31 };
	uint8_t ciphertext[8];

	cr_des_encrypt(plaintext, key, ciphertext);
	ck_assert_mem_eq(ciphertext, expected, 8);
}

END_TEST START_TEST(encryption_10)
{
	const uint8_t key[] =
	    { 0x59, 0x16, 0xb8, 0x27, 0x7e, 0xfe, 0xa0, 0xf9 };
	const uint8_t plaintext[] =
	    { 0xcd, 0xc4, 0x4, 0xd, 0xc7, 0x46, 0x3f, 0x53 };
	const uint8_t expected[] =
	    { 0xe1, 0x24, 0xb1, 0x39, 0x35, 0x38, 0x92, 0xfb };
	uint8_t ciphertext[8];

	cr_des_encrypt(plaintext, key, ciphertext);
	ck_assert_mem_eq(ciphertext, expected, 8);
}

END_TEST START_TEST(decryption_1)
{
	const uint8_t key[] = { 0x15, 0x58, 0xf1, 0xc, 0xe4, 0x9, 0x1b, 0x6f };
	const uint8_t ciphertext[] =
	    { 0x85, 0xb7, 0xc9, 0xdd, 0x64, 0x4d, 0x6e, 0xdc };
	const uint8_t expected[] =
	    { 0xd9, 0xfa, 0x91, 0x94, 0xfc, 0xb, 0x67, 0xa6 };
	uint8_t plaintext[8];

	cr_des_decrypt(ciphertext, key, plaintext);
	ck_assert_mem_eq(plaintext, expected, 8);
}

END_TEST START_TEST(decryption_2)
{
	const uint8_t key[] =
	    { 0xcd, 0xb0, 0xb0, 0xdb, 0x61, 0x6f, 0x79, 0xbd };
	const uint8_t ciphertext[] =
	    { 0x92, 0xec, 0xd1, 0x6, 0x18, 0x4e, 0x44, 0xe2 };
	const uint8_t expected[] =
	    { 0xe4, 0xd7, 0xf7, 0x48, 0x52, 0xcf, 0x9e, 0xb5 };
	uint8_t plaintext[8];

	cr_des_decrypt(ciphertext, key, plaintext);
	ck_assert_mem_eq(plaintext, expected, 8);
}

END_TEST START_TEST(decryption_3)
{
	const uint8_t key[] = { 0xf, 0xb9, 0x17, 0x80, 0xec, 0x3b, 0x62, 0x79 };
	const uint8_t ciphertext[] =
	    { 0xe3, 0x40, 0x79, 0x8, 0xb5, 0x38, 0xad, 0x31 };
	const uint8_t expected[] =
	    { 0x43, 0x22, 0x19, 0x0, 0xf0, 0xf5, 0x93, 0xd3 };
	uint8_t plaintext[8];

	cr_des_decrypt(ciphertext, key, plaintext);
	ck_assert_mem_eq(plaintext, expected, 8);
}

END_TEST START_TEST(decryption_4)
{
	const uint8_t key[] =
	    { 0xa3, 0x12, 0xb7, 0x1c, 0x25, 0x57, 0x6f, 0xd2 };
	const uint8_t ciphertext[] =
	    { 0xaf, 0xb7, 0x31, 0x0, 0xad, 0xdd, 0x4, 0x32 };
	const uint8_t expected[] =
	    { 0xc2, 0xf5, 0x76, 0xcf, 0x21, 0x23, 0x5b, 0x17 };
	uint8_t plaintext[8];

	cr_des_decrypt(ciphertext, key, plaintext);
	ck_assert_mem_eq(plaintext, expected, 8);
}

END_TEST START_TEST(decryption_5)
{
	const uint8_t key[] =
	    { 0xf3, 0x56, 0x93, 0x5b, 0x86, 0x5f, 0xf9, 0x78 };
	const uint8_t ciphertext[] =
	    { 0x3, 0x63, 0x3a, 0x6f, 0x73, 0xd3, 0xc1, 0x15 };
	const uint8_t expected[] =
	    { 0x3f, 0x8b, 0x51, 0xdd, 0xa7, 0x92, 0x83, 0x5e };
	uint8_t plaintext[8];

	cr_des_decrypt(ciphertext, key, plaintext);
	ck_assert_mem_eq(plaintext, expected, 8);
}

END_TEST START_TEST(decryption_6)
{
	const uint8_t key[] =
	    { 0xc6, 0xc5, 0xc9, 0x55, 0x4d, 0x3b, 0x78, 0xeb };
	const uint8_t ciphertext[] =
	    { 0xdc, 0xd4, 0x35, 0xe1, 0x64, 0xfc, 0x98, 0xac };
	const uint8_t expected[] =
	    { 0x39, 0xf, 0x13, 0xb8, 0x42, 0xa1, 0x3, 0x2a };
	uint8_t plaintext[8];

	cr_des_decrypt(ciphertext, key, plaintext);
	ck_assert_mem_eq(plaintext, expected, 8);
}

END_TEST START_TEST(decryption_7)
{
	const uint8_t key[] = { 0x2, 0x33, 0xfb, 0xe, 0x41, 0x28, 0xb0, 0x2 };
	const uint8_t ciphertext[] =
	    { 0x70, 0x4f, 0x86, 0x67, 0x2c, 0x9, 0x43, 0x39 };
	const uint8_t expected[] =
	    { 0x87, 0xf, 0xf7, 0x76, 0x7, 0x12, 0x3b, 0x15 };
	uint8_t plaintext[8];

	cr_des_decrypt(ciphertext, key, plaintext);
	ck_assert_mem_eq(plaintext, expected, 8);
}

END_TEST START_TEST(decryption_8)
{
	const uint8_t key[] =
	    { 0xd4, 0xca, 0x30, 0xe0, 0x97, 0xf4, 0x28, 0x7d };
	const uint8_t ciphertext[] =
	    { 0xeb, 0xe2, 0x8c, 0x53, 0xa4, 0x45, 0xbf, 0x87 };
	const uint8_t expected[] =
	    { 0xc3, 0x84, 0xf0, 0xbf, 0xf2, 0x47, 0xe9, 0xf2 };
	uint8_t plaintext[8];

	cr_des_decrypt(ciphertext, key, plaintext);
	ck_assert_mem_eq(plaintext, expected, 8);
}

END_TEST START_TEST(decryption_9)
{
	const uint8_t key[] =
	    { 0xf0, 0xd7, 0xda, 0xdc, 0x11, 0x35, 0xe5, 0xb8 };
	const uint8_t ciphertext[] =
	    { 0x38, 0x58, 0xd6, 0xfe, 0x5a, 0xb2, 0x17, 0xa1 };
	const uint8_t expected[] =
	    { 0x2a, 0xea, 0xf, 0xfd, 0x91, 0x8d, 0xde, 0x5e };
	uint8_t plaintext[8];

	cr_des_decrypt(ciphertext, key, plaintext);
	ck_assert_mem_eq(plaintext, expected, 8);
}

END_TEST START_TEST(decryption_10)
{
	const uint8_t key[] =
	    { 0xd0, 0x7f, 0xa3, 0xca, 0xd3, 0xe2, 0x81, 0x86 };
	const uint8_t ciphertext[] =
	    { 0x1b, 0x58, 0x7f, 0x85, 0xc1, 0x4, 0xc0, 0xc4 };
	const uint8_t expected[] =
	    { 0xf7, 0x4b, 0x3e, 0x1e, 0x7, 0xf3, 0x70, 0x30 };
	uint8_t plaintext[8];

	cr_des_decrypt(ciphertext, key, plaintext);
	ck_assert_mem_eq(plaintext, expected, 8);
}

END_TEST START_TEST(encryption_bounds)
{
	const uint8_t key[] =
	    { 0x0f, 0x15, 0x71, 0xc9, 0x47, 0xd9, 0xe8, 0x59 };
	const uint8_t plaintext[] =
	    { 02, 0x46, 0x8a, 0xce, 0xec, 0xa8, 0x64, 0x20 };
	const uint8_t expected[] =
	    { 0xda, 0x02, 0xce, 0x3a, 0x89, 0xec, 0xac, 0x3b };
	uint8_t ciphertext[16];
	uint8_t zbuf[8];

	memset(ciphertext, 0, 16);
	memset(zbuf, 0, 8);

	cr_des_encrypt(plaintext, key, ciphertext);
	ck_assert_mem_eq(ciphertext, expected, 8);
	ck_assert_mem_eq(ciphertext + 8, zbuf, 8);
}

END_TEST START_TEST(decryption_bounds)
{
	const uint8_t key[] = { 0x15, 0x58, 0xf1, 0xc, 0xe4, 0x9, 0x1b, 0x6f };
	const uint8_t ciphertext[] =
	    { 0x85, 0xb7, 0xc9, 0xdd, 0x64, 0x4d, 0x6e, 0xdc };
	const uint8_t expected[] =
	    { 0xd9, 0xfa, 0x91, 0x94, 0xfc, 0xb, 0x67, 0xa6 };
	uint8_t plaintext[16];
	uint8_t zbuf[8];

	memset(plaintext, 0, 16);
	memset(zbuf, 0, 8);

	cr_des_decrypt(ciphertext, key, plaintext);
	ck_assert_mem_eq(plaintext, expected, 8);
	ck_assert_mem_eq(plaintext + 8, zbuf, 8);
}

END_TEST START_TEST(encryption_decryption)
{
	uint8_t key[8];
	uint8_t ciphertext[8];
	uint8_t plaintext[8];
	uint8_t decypted[8];

	for (int i = 0; i < 10; ++i) {
		ck_assert_int_eq(cr_rand_bytes(key, 8), 0);
		ck_assert_int_eq(cr_rand_bytes(plaintext, 8), 0);

		cr_des_encrypt(plaintext, key, ciphertext);
		cr_des_decrypt(ciphertext, key, decypted);
		ck_assert_mem_eq(plaintext, decypted, 8);
	}
}

END_TEST Suite *hashset_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("DES");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, constants);

	tcase_add_test(tc_core, encryption_1);
	tcase_add_test(tc_core, encryption_2);
	tcase_add_test(tc_core, encryption_3);
	tcase_add_test(tc_core, encryption_4);
	tcase_add_test(tc_core, encryption_5);
	tcase_add_test(tc_core, encryption_6);
	tcase_add_test(tc_core, encryption_7);
	tcase_add_test(tc_core, encryption_8);
	tcase_add_test(tc_core, encryption_9);
	tcase_add_test(tc_core, encryption_10);

	tcase_add_test(tc_core, decryption_1);
	tcase_add_test(tc_core, decryption_2);
	tcase_add_test(tc_core, decryption_3);
	tcase_add_test(tc_core, decryption_4);
	tcase_add_test(tc_core, decryption_5);
	tcase_add_test(tc_core, decryption_6);
	tcase_add_test(tc_core, decryption_7);
	tcase_add_test(tc_core, decryption_8);
	tcase_add_test(tc_core, decryption_9);
	tcase_add_test(tc_core, decryption_10);

	tcase_add_test(tc_core, encryption_bounds);
	tcase_add_test(tc_core, decryption_bounds);
	tcase_add_test(tc_core, encryption_decryption);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s = hashset_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

#include <check.h>
#include <crypt/rand.h>
#include <crypt/stream.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

START_TEST(rc4_init)
{
	struct cr_rc4_s *cipher;
	const char *key = "somenicekey";

	cipher = cr_rc4_new((unsigned char *)key, strlen(key));
	ck_assert_ptr_nonnull(cipher);
	cr_rc4_destroy(cipher);
}

END_TEST START_TEST(simple_encryption)
{
	struct cr_rc4_s *cipher;
	const char *plaintext = "The quick brown fox jumps over the lazy dog.";
	unsigned char key[] = { 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x69 };
	unsigned char expected[] = {
		0x2a, 0xc2, 0xfe, 0xcd, 0xd8, 0xfb, 0xb8,
		0x46, 0x38, 0xe3, 0xa4, 0x82, 0xe, 0xb2, 0x5,
		0xcc, 0x8e, 0x29, 0xc2, 0x8b, 0x9d, 0x5d, 0x6b,
		0x2e, 0xf9, 0x74, 0xf3, 0x11, 0x96, 0x49, 0x71,
		0xc9, 0xe, 0x8b, 0x9c, 0xa1, 0x64, 0x67, 0xef, 0x2d, 0xc6, 0xfc,
		0x35, 0x20,
	};
	unsigned char ciphertext[50];

	cipher = cr_rc4_new(key, sizeof(key));
	ck_assert_ptr_nonnull(cipher);
	cr_rc4_encrypt(cipher, (unsigned char *)plaintext,
		       strlen(plaintext), ciphertext);
	cr_rc4_destroy(cipher);

	ck_assert_mem_eq(ciphertext, expected, sizeof(expected));
}

END_TEST START_TEST(simple_decryption)
{
	struct cr_rc4_s *cipher;
	const char *expected = "The quick brown fox jumps over the lazy dog.";
	unsigned char key[] = { 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x69 };
	unsigned char ciphertext[] = {
		0x2a, 0xc2, 0xfe, 0xcd, 0xd8, 0xfb, 0xb8, 0x46,
		0x38, 0xe3, 0xa4, 0x82, 0x0e, 0xb2, 0x05, 0xcc,
		0x8e, 0x29, 0xc2, 0x8b, 0x9d, 0x5d, 0x6b, 0x2e,
		0xf9, 0x74, 0xf3, 0x11, 0x96, 0x49, 0x71, 0xc9,
		0x0e, 0x8b, 0x9c, 0xa1, 0x64, 0x67, 0xef, 0x2d,
		0xc6, 0xfc, 0x35, 0x20
	};
	unsigned char plaintext[50];

	cipher = cr_rc4_new(key, sizeof(key));
	ck_assert_ptr_nonnull(cipher);
	cr_rc4_decrypt(cipher, ciphertext, sizeof(ciphertext), plaintext);
	cr_rc4_destroy(cipher);

	ck_assert_mem_eq(plaintext, expected, sizeof(ciphertext));
}

END_TEST START_TEST(encryption_decryption)
{
	struct cr_rc4_s *cipher;
	const char *plaintext = "The quick brown fox jumps over the lazy dog.";
	unsigned char key[] = { 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x69 };
	unsigned char buf[50], buf2[50];

	cipher = cr_rc4_new(key, sizeof(key));
	ck_assert_ptr_nonnull(cipher);
	cr_rc4_encrypt(cipher, (unsigned char *)plaintext,
		       strlen(plaintext), buf);
	cr_rc4_destroy(cipher);

	cipher = cr_rc4_new(key, sizeof(key));
	ck_assert_ptr_nonnull(cipher);
	cr_rc4_decrypt(cipher, buf, strlen(plaintext), buf2);
	cr_rc4_destroy(cipher);

	ck_assert_mem_eq(plaintext, buf2, strlen(plaintext));
}

END_TEST START_TEST(multiple_encryption_decryption)
{
	struct cr_rc4_s *cipher;
	unsigned char in[50], enc[50], out[50], key[300];

	for (int i = 0; i < 10; ++i) {
		ck_assert_int_eq(cr_rand_bytes(in, 50), 0);
		ck_assert_int_eq(cr_rand_bytes(key, 300), 0);

		cipher = cr_rc4_new(key, sizeof(key));
		ck_assert_ptr_nonnull(cipher);
		cr_rc4_encrypt(cipher, in, sizeof(in), enc);
		cr_rc4_destroy(cipher);

		cipher = cr_rc4_new(key, sizeof(key));
		ck_assert_ptr_nonnull(cipher);
		cr_rc4_decrypt(cipher, enc, sizeof(enc), out);
		cr_rc4_destroy(cipher);

		ck_assert_mem_eq(in, out, sizeof(in));
	}
}

END_TEST START_TEST(zero_len_encryption)
{
	struct cr_rc4_s *cipher;
	const char *plaintext = "The quick brown fox jumps over the lazy dog.";
	unsigned char key[] = { 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x69 };
	unsigned char expected[50] = { 0x0 };
	unsigned char ciphertext[50] = { 0x0 };

	cipher = cr_rc4_new(key, sizeof(key));
	ck_assert_ptr_nonnull(cipher);
	cr_rc4_encrypt(cipher, (unsigned char *)plaintext, 0, ciphertext);
	cr_rc4_destroy(cipher);

	ck_assert_mem_eq(ciphertext, expected, sizeof(expected));
}

END_TEST START_TEST(zero_len_decryption)
{
	struct cr_rc4_s *cipher;
	unsigned char expected[50] = { 0x0 };
	unsigned char key[] = { 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x69 };
	unsigned char ciphertext[] = {
		0x2a, 0xc2, 0xfe, 0xcd, 0xd8, 0xfb, 0xb8, 0x46,
		0x38, 0xe3, 0xa4, 0x82, 0x0e, 0xb2, 0x05, 0xcc,
		0x8e, 0x29, 0xc2, 0x8b, 0x9d, 0x5d, 0x6b, 0x2e,
		0xf9, 0x74, 0xf3, 0x11, 0x96, 0x49, 0x71, 0xc9,
		0x0e, 0x8b, 0x9c, 0xa1, 0x64, 0x67, 0xef, 0x2d,
		0xc6, 0xfc, 0x35, 0x20
	};
	unsigned char plaintext[50] = { 0x0 };

	cipher = cr_rc4_new(key, sizeof(key));
	ck_assert_ptr_nonnull(cipher);
	cr_rc4_decrypt(cipher, ciphertext, 0, plaintext);
	cr_rc4_destroy(cipher);

	ck_assert_mem_eq(plaintext, expected, sizeof(expected));
}

END_TEST START_TEST(bounds_encryption)
{
	struct cr_rc4_s *cipher;
	const char *plaintext = "The quick brown fox jumps over the lazy dog.";
	unsigned char key[] = { 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x69 };
	unsigned char expected[] = {
		0x2a, 0xc2, 0xfe, 0xcd, 0xd8, 0xfb, 0xb8,
		0x46, 0x38, 0xe3, 0xa4, 0x82, 0xe, 0xb2, 0x5,
		0xcc, 0x8e, 0x29, 0xc2, 0x8b, 0x9d, 0x5d, 0x6b,
		0x2e, 0xf9, 0x74, 0xf3, 0x11, 0x96, 0x49, 0x71,
		0xc9, 0xe, 0x8b, 0x9c, 0xa1, 0x64, 0x67, 0xef, 0x2d, 0xc6, 0xfc,
		0x35, 0x20,
	};
	unsigned char ciphertext[50] = { 0x0 };
	unsigned char zbuf[50] = { 0x0 };

	cipher = cr_rc4_new(key, sizeof(key));
	ck_assert_ptr_nonnull(cipher);
	cr_rc4_encrypt(cipher, (unsigned char *)plaintext,
		       strlen(plaintext), ciphertext);
	cr_rc4_destroy(cipher);

	ck_assert_mem_eq(ciphertext, expected, sizeof(expected));
	ck_assert_mem_eq(ciphertext + sizeof(expected), zbuf,
			 sizeof(ciphertext) - sizeof(expected));
}

END_TEST START_TEST(bounds_decryption)
{
	struct cr_rc4_s *cipher;
	const char *expected = "The quick brown fox jumps over the lazy dog.";
	unsigned char key[] = { 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x69 };
	unsigned char ciphertext[] = {
		0x2a, 0xc2, 0xfe, 0xcd, 0xd8, 0xfb, 0xb8, 0x46,
		0x38, 0xe3, 0xa4, 0x82, 0x0e, 0xb2, 0x05, 0xcc,
		0x8e, 0x29, 0xc2, 0x8b, 0x9d, 0x5d, 0x6b, 0x2e,
		0xf9, 0x74, 0xf3, 0x11, 0x96, 0x49, 0x71, 0xc9,
		0x0e, 0x8b, 0x9c, 0xa1, 0x64, 0x67, 0xef, 0x2d,
		0xc6, 0xfc, 0x35, 0x20
	};
	unsigned char plaintext[50] = { 0x0 };
	unsigned char zbuf[50] = { 0x0 };

	cipher = cr_rc4_new(key, sizeof(key));
	ck_assert_ptr_nonnull(cipher);
	cr_rc4_decrypt(cipher, ciphertext, sizeof(ciphertext), plaintext);
	cr_rc4_destroy(cipher);

	ck_assert_mem_eq(plaintext, expected, sizeof(ciphertext));
	ck_assert_mem_eq(plaintext + sizeof(ciphertext), zbuf,
			 sizeof(plaintext) - sizeof(ciphertext));
}

END_TEST Suite *hashset_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("RC4");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, rc4_init);

	tcase_add_test(tc_core, simple_encryption);
	tcase_add_test(tc_core, simple_decryption);
	tcase_add_test(tc_core, encryption_decryption);
	tcase_add_test(tc_core, multiple_encryption_decryption);

	tcase_add_test(tc_core, zero_len_encryption);
	tcase_add_test(tc_core, zero_len_decryption);
	tcase_add_test(tc_core, bounds_encryption);
	tcase_add_test(tc_core, bounds_decryption);

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

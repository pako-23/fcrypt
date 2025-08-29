#include <check.h>
#include <crypt/rand.h>
#include <crypt/stream.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

START_TEST(simple_encryption)
{
	unsigned char plaintext[] = "Hello, World!!!!!";
	unsigned char key[] = "longlongkeyforotp";
	unsigned char expected[] = {
		36, 10, 2, 11, 3, 67,
		78, 48, 4, 23, 21, 2,
		78, 83, 78, 85, 81
	};
	unsigned char ciphertext[20];
	size_t len = sizeof(expected);

	memset(ciphertext, 0, 20);
	cr_otp(plaintext, key, ciphertext, len);

	ck_assert_mem_eq(ciphertext, expected, len);
}

END_TEST START_TEST(simple_decryption)
{
	unsigned char expected[] = "Hello, World!!!!!";
	unsigned char key[] = "longlongkeyforotp";
	unsigned char ciphertext[] = {
		36, 10, 2, 11, 3, 67,
		78, 48, 4, 23, 21, 2,
		78, 83, 78, 85, 81
	};
	unsigned char plaintext[20] = { 0 };
	size_t len = sizeof(ciphertext);

	memset(plaintext, 0, 20);
	cr_otp(ciphertext, key, plaintext, len);

	ck_assert_mem_eq(plaintext, expected, len);
}

END_TEST START_TEST(len_respected)
{
	unsigned char plaintext[] = "Hello, World!!!!!";
	unsigned char key[] = "longlongkeyforotp";
	unsigned char expected[] = {
		36, 10, 2, 11, 3, 67,
		78, 48, 4, 23, 21, 2,
		78, 83, 78, 85, 81
	};
	unsigned char ciphertext[20] = { 0 };
	unsigned char zbuf[20] = { 0 };
	size_t len = sizeof(expected);

	memset(ciphertext, 0, 20);
	memset(zbuf, 0, 20);
	cr_otp(plaintext, key, ciphertext, len);

	ck_assert_mem_eq(ciphertext, expected, len);
	ck_assert_mem_eq(ciphertext + len, zbuf, sizeof(zbuf) - len);
}

END_TEST START_TEST(plain_untouched)
{
	unsigned char plaintext[] = "Hello, World!!!!!";
	unsigned char key[] = "longlongkeyforotp";
	unsigned char expected[] = {
		36, 10, 2, 11, 3, 67,
		78, 48, 4, 23, 21, 2,
		78, 83, 78, 85, 81
	};
	unsigned char ciphertext[20];
	unsigned char buf[20];
	size_t len = sizeof(expected);

	memset(ciphertext, 0, 20);
	strcpy((char *)buf, (char *)plaintext);
	cr_otp(plaintext, key, ciphertext, len);

	ck_assert_mem_eq(ciphertext, expected, len);
	ck_assert_mem_eq(plaintext, buf, len);
}

END_TEST START_TEST(key_untouched)
{
	unsigned char plaintext[] = "Hello, World!!!!!";
	unsigned char key[] = "longlongkeyforotp";
	unsigned char expected[] = {
		36, 10, 2, 11, 3, 67,
		78, 48, 4, 23, 21, 2,
		78, 83, 78, 85, 81
	};
	unsigned char ciphertext[20];
	unsigned char buf[20];
	size_t len = sizeof(expected);

	memset(ciphertext, 0, 20);
	strcpy((char *)buf, (char *)key);
	cr_otp(plaintext, key, ciphertext, len);

	ck_assert_mem_eq(ciphertext, expected, len);
	ck_assert_mem_eq(key, buf, len);
}

END_TEST START_TEST(zero_len)
{
	unsigned char plaintext[] = "Hello, World!!!!!";
	unsigned char key[] = "longlongkeyforotp";
	unsigned char out[10];

	cr_otp(plaintext, key, out, 0);

	ck_assert_mem_eq(plaintext, "Hello, World!!!!!", sizeof(plaintext));
	ck_assert_mem_eq(key, "longlongkeyforotp", sizeof(key));
}

END_TEST START_TEST(key_all_zeros)
{
	unsigned char plaintext[] = "Hello, World!!!!!";
	unsigned char key[20];
	size_t len = sizeof(plaintext);
	unsigned char out[20];

	memset(key, 0, 20);
	cr_otp(plaintext, key, out, len);

	ck_assert_mem_eq(plaintext, out, len);
}

END_TEST START_TEST(random_key)
{
	unsigned char plaintext[20];
	unsigned char key[20];
	unsigned char out[20];
	unsigned char expected[20];

	for (int i = 0; i < 10; ++i) {
		ck_assert_int_eq(cr_rand_bytes(plaintext, 20), 0);
		ck_assert_int_eq(cr_rand_bytes(key, 20), 0);

		for (int j = 0; j < 20; ++j)
			expected[j] = plaintext[j] ^ key[j];

		cr_otp(plaintext, key, out, 20);

		ck_assert_mem_eq(out, expected, 20);
	}
}

END_TEST Suite *hashset_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("OneTimePad");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, simple_encryption);
	tcase_add_test(tc_core, simple_decryption);
	tcase_add_test(tc_core, len_respected);
	tcase_add_test(tc_core, plain_untouched);
	tcase_add_test(tc_core, key_untouched);
	tcase_add_test(tc_core, zero_len);
	tcase_add_test(tc_core, key_all_zeros);
	tcase_add_test(tc_core, random_key);

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

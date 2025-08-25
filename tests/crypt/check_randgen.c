#include <check.h>
#include <stdlib.h>
#include <crypt/rand.h>

START_TEST(simple_call)
{
	unsigned char buf[16];
	unsigned char zbuf[16];

	memset(buf, 0, 16);
	memset(zbuf, 0, 16);
	ck_assert_int_eq(cr_rand_bytes(buf, 16), 0);
	ck_assert_mem_ne(buf, zbuf, 16);
}

END_TEST START_TEST(longer_buf)
{
	unsigned char buf[32];
	unsigned char zbuf[16];

	memset(buf, 0, 32);
	memset(zbuf, 0, 16);
	ck_assert_int_eq(cr_rand_bytes(buf, 16), 0);
	ck_assert_mem_ne(buf, zbuf, 16);
	ck_assert_mem_eq(buf + 16, zbuf, 16);
}

END_TEST START_TEST(uniqueness)
{
	unsigned char buf1[52];
	unsigned char buf2[52];
	unsigned char zbuf[52];

	memset(buf1, 0, 52);
	memset(buf2, 0, 52);
	memset(zbuf, 0, 52);
	ck_assert_int_eq(cr_rand_bytes(buf1, 52), 0);
	ck_assert_int_eq(cr_rand_bytes(buf2, 52), 0);
	ck_assert_mem_ne(buf1, zbuf, 52);
	ck_assert_mem_ne(buf2, zbuf, 52);
	ck_assert_mem_ne(buf1, buf2, 52);
}

END_TEST START_TEST(zero_len)
{
	unsigned char buf[10];
	unsigned char zbuf[10];

	memset(buf, 0, 10);
	memset(zbuf, 0, 10);
	ck_assert_int_eq(cr_rand_bytes(buf, 0), 0);
	ck_assert_mem_eq(buf, zbuf, 10);
}

END_TEST Suite *hashset_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("RandGen");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, simple_call);
	tcase_add_test(tc_core, longer_buf);
	tcase_add_test(tc_core, uniqueness);
	tcase_add_test(tc_core, zero_len);

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

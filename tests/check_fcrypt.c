#include <fcrypt.h>
#include <check.h>
#include <crypt/des.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define HELP_PAGE                                                              \
  "Usage: fcrypt [options]\n\n"                                                \
  "Options:\n"                                                                 \
  "  -m <mode>, --mode <mode>\n"                                               \
  "       The cipher operation mode for block ciphers: ecb, cbc, cfb,\n"       \
  "       ofb. (default: cbc)\n"                                               \
  "  -c <cipher>, --cipher <cipher>\n"                                         \
  "       The cipher to use: otp, rc4, des, tdea. (required)\n"                \
  "  -d, --decrypt\n"                                                          \
  "       Run in decryption mode.\n"                                           \
  "  -i <file>, --in <file>\n"                                                 \
  "       The file to encrypt or decrypt. (required)\n"                        \
  "  -o <file>, --out <file>\n"                                                \
  "       The file which will contain the encryption/decryption output.\n"     \
  "       (required)\n"                                                        \
  "  -k <file>, --key <file>\n"                                                \
  "       In encryption, it is the file which will contain a randomly\n"       \
  "       generated key. In decryption, it is the file from which the\n"       \
  "       key will be read. For rc4, this value will be used as a key.\n"      \
  "       (required)\n"                                                        \
  "  -h, --help\n"                                                             \
  "       Display this help and exit\n"

static void compare_file_str(const char *fname, const char *expected,
			     size_t len)
{
	FILE *fp = fopen(fname, "r");

	ck_assert_ptr_nonnull(fp);

	fseek(fp, 0, SEEK_END);
	long size = ftell(fp);
	rewind(fp);

	ck_assert_int_eq(size, len);
	char *buf = malloc(size);

	ck_assert_ptr_nonnull(buf);

	fread(buf, 1, size, fp);
	fclose(fp);

	ck_assert_mem_eq(buf, expected, len);
	free(buf);
}

static void compare_files(const char *first, const char *second)
{
	FILE *fp1, *fp2;
	size_t nread1, nread2;
	unsigned char buf1[BUFSIZ], buf2[BUFSIZ];

	fp1 = fopen(first, "rb");
	ck_assert_ptr_nonnull(fp1);

	fp2 = fopen(second, "rb");
	ck_assert_ptr_nonnull(fp2);

	fseek(fp1, 0, SEEK_END);
	long size1 = ftell(fp1);
	rewind(fp1);

	fseek(fp2, 0, SEEK_END);
	long size2 = ftell(fp1);
	rewind(fp2);

	while ((nread1 = fread(buf1, 1, sizeof(buf1), fp1)) &&
	       (nread2 = fread(buf2, 1, sizeof(buf2), fp2))) {
		ck_assert_int_eq(nread1, nread2);
		ck_assert_mem_eq(buf1, buf2, nread1);
	}

	ck_assert_int_eq(ferror(fp1), 0);
	ck_assert_int_eq(ferror(fp2), 0);

	fclose(fp1);
	fclose(fp2);

}

static void rand_file(const char *fname, size_t len)
{
	FILE *fp;
	unsigned char buf[BUFSIZ];
	size_t left;

	fp = fopen(fname, "wb");
	ck_assert_ptr_nonnull(fp);

	time(NULL);

	while (len > 0) {
		left = len < BUFSIZ ? len : BUFSIZ;

		for (size_t i = 0; i < left; ++i)
			buf[i] = rand() % UCHAR_MAX;

		ck_assert_int_eq(fwrite(buf, 1, left, fp), left);
		len -= left;
	}

	fclose(fp);
}

START_TEST(help_page_long)
{
	char *argv[] = { "fcrypt", "--help", NULL };
	int argc = 2;
	FILE *out = freopen("help_page_long", "wb", stdout);

	ck_assert_ptr_nonnull(out);
	ck_assert_int_eq(fcrypt_main(argc, argv), EXIT_SUCCESS);
	fclose(out);

	compare_file_str("help_page_long", HELP_PAGE, strlen(HELP_PAGE));
	remove("help_page_long");
}

END_TEST START_TEST(help_page_short)
{
	char progname[] = "fcrypt";
	char help[] = "-h";
	char *argv[] = { "fcrypt", "-h", NULL };
	int argc = 2;
	FILE *out = freopen("help_page_short", "wb", stdout);

	ck_assert_ptr_nonnull(out);
	ck_assert_int_eq(fcrypt_main(argc, argv), EXIT_SUCCESS);
	fclose(out);

	compare_file_str("help_page_short", HELP_PAGE, strlen(HELP_PAGE));
	remove("help_page_short");
}

END_TEST START_TEST(invalid_flag1)
{
	char *argv[] = { "fcrypt", "-s", NULL };
	int argc = 2;
	FILE *out = freopen("invalid_flag1", "wb", stdout);
	const char *expected = "unknown option: -s\n" HELP_PAGE;

	ck_assert_ptr_nonnull(out);
	ck_assert_int_eq(fcrypt_main(argc, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("invalid_flag1", expected, strlen(expected));
	remove("invalid_flag1");
}

END_TEST START_TEST(invalid_flag2)
{
	char *argv[] = { "fcrypt", "flag", NULL };
	int argc = 2;
	FILE *out = freopen("invalid_flag2", "wb", stdout);
	const char *expected = "unknown option: flag\n" HELP_PAGE;

	ck_assert_ptr_nonnull(out);
	ck_assert_int_eq(fcrypt_main(argc, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("invalid_flag2", expected, strlen(expected));
	remove("invalid_flag2");
}

END_TEST START_TEST(missing_key)
{
	char *argv[] =
	    { "fcrypt", "--cipher", "otp", "--in", "infile", "--out", "outfile",
	 NULL };
	int argc = 7;
	FILE *out = freopen("missing_key", "wb", stdout);
	const char *expected = "a key/keyfile is required\n" HELP_PAGE;

	ck_assert_ptr_nonnull(out);
	ck_assert_int_eq(fcrypt_main(argc, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("missing_key", expected, strlen(expected));
	remove("missing_key");
}

END_TEST START_TEST(missing_cipher)
{
	char *argv[] =
	    { "fcrypt", "--key", "keyfile", "--in", "infile", "--out",
	 "outfile", NULL };
	int argc = 7;
	FILE *out = freopen("missing_cipher", "wb", stdout);
	const char *expected = "a cipher is required\n" HELP_PAGE;

	ck_assert_ptr_nonnull(out);
	ck_assert_int_eq(fcrypt_main(argc, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("missing_cipher", expected, strlen(expected));
	remove("missing_cipher");
}

END_TEST START_TEST(missing_in)
{
	char *argv[] =
	    { "fcrypt", "--key", "keyfile", "--cipher", "otp", "--out",
	 "outfile", NULL };
	int argc = 7;
	FILE *out = freopen("missing_in", "wb", stdout);
	const char *expected = "an input file is required\n" HELP_PAGE;

	ck_assert_ptr_nonnull(out);
	ck_assert_int_eq(fcrypt_main(argc, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("missing_in", expected, strlen(expected));
	remove("missing_in");
}

END_TEST START_TEST(missing_out)
{
	char *argv[] =
	    { "fcrypt", "--key", "keyfile", "--cipher", "otp", "--in", "infile",
	 NULL };
	int argc = 7;
	FILE *out = freopen("missing_out", "wb", stdout);
	const char *expected = "an output file is required\n" HELP_PAGE;

	ck_assert_ptr_nonnull(out);
	ck_assert_int_eq(fcrypt_main(argc, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("missing_out", expected, strlen(expected));
	remove("missing_out");
}

END_TEST START_TEST(invalid_mode)
{
	char *argv[] =
	    { "fcrypt", "--key", "invalid-mode-key", "-c", "des", "--in",
	 "invalid-mode-in", "-o", "invalid-mode-out", "-m", "anonmode", NULL };
	int argc = 11;
	FILE *out = freopen("invalid_mode", "wb", stdout);
	const char *expected = "unknown operation mode: anonmode\n" HELP_PAGE;

	ck_assert_ptr_nonnull(out);
	ck_assert_int_eq(fcrypt_main(argc, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("invalid_mode", expected, strlen(expected));
	remove("invalid_mode");
}

END_TEST START_TEST(invalid_cipher)
{
	char *argv[] =
	    { "fcrypt", "--key", "invalid-cipher-key", "--in",
	 "invalid-cipher-in", "-o", "invalid-cipher-out", "-c", "anoncipher",
	 NULL };
	int argc = 9;
	FILE *out = freopen("invalid_cipher", "wb", stdout);
	const char *expected = "unknown cipher: anoncipher\n" HELP_PAGE;

	ck_assert_ptr_nonnull(out);
	ck_assert_int_eq(fcrypt_main(argc, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("invalid_cipher", expected, strlen(expected));
	remove("invalid_cipher");
}

END_TEST START_TEST(encrypt_no_mode)
{
	char *argv1[] =
	    { "fcrypt", "--key", "des-enc-no-mode-key", "--cipher", "des",
		"--in", "des-enc-no-mode-in", "--out", "des-enc-no-mode-out",
		    NULL
	};
	char *argv2[] =
	    { "fcrypt", "-d", "--key", "des-enc-no-mode-key", "--cipher", "des",
	"--in", "des-enc-no-mode-out", "--out", "des-enc-no-mode-res", "-m",
	"cbc", NULL };

	rand_file("des-enc-no-mode-in", 100);

	ck_assert_int_eq(fcrypt_main(9, argv1), EXIT_SUCCESS);
	ck_assert_int_eq(fcrypt_main(12, argv2), EXIT_SUCCESS);

	compare_files("des-enc-no-mode-in", "des-enc-no-mode-res");
	remove("des-enc-no-mode-key");
	remove("des-enc-no-mode-in");
	remove("des-enc-no-mode-out");
	remove("des-enc-no-mode-res");
}

END_TEST START_TEST(decrypt_no_mode)
{
	char *argv1[] =
	    { "fcrypt", "--key", "des-dec-no-mode-key", "--cipher", "des",
		"--in", "des-dec-no-mode-in", "--out", "des-dec-no-mode-out",
		    "-m", "cbc", NULL
	};
	char *argv2[] =
	    { "fcrypt", "-d", "--key", "des-dec-no-mode-key", "--cipher", "des",
	"--in", "des-dec-no-mode-out", "--out", "des-dec-no-mode-res", NULL };

	rand_file("des-dec-no-mode-in", 100);

	ck_assert_int_eq(fcrypt_main(11, argv1), EXIT_SUCCESS);
	ck_assert_int_eq(fcrypt_main(10, argv2), EXIT_SUCCESS);

	compare_files("des-dec-no-mode-in", "des-dec-no-mode-res");
	remove("des-dec-no-mode-key");
	remove("des-dec-no-mode-in");
	remove("des-dec-no-mode-out");
	remove("des-dec-no-mode-res");
}

END_TEST START_TEST(otp_encrypt_decrypt)
{
	char *argv1[] = { "fcrypt", "--key", "otp-key", "--cipher", "otp",
		"--in", "otp-infile", "--out", "otp-outfile", NULL
	};
	char *argv2[] =
	    { "fcrypt", "-d", "--key", "otp-key", "--cipher", "otp", "--in",
	"otp-outfile", "--out", "otp-res", NULL };

	rand_file("otp-infile", BUFSIZ * 3 + 123);

	ck_assert_int_eq(fcrypt_main(9, argv1), EXIT_SUCCESS);
	ck_assert_int_eq(fcrypt_main(10, argv2), EXIT_SUCCESS);

	compare_files("otp-res", "otp-infile");
	remove("otp-infile");
	remove("otp-outfile");
	remove("otp-key");
	remove("otp-res");
}

END_TEST START_TEST(otp_encrypt_missing_input)
{
	char *argv[] = { "fcrypt", "--key", "otp-key", "--cipher", "otp",
		"--in", "missing-in-enc", "--out", "otp-outfile", NULL
	};
	const char expected[] = "failed to open input file\n";

	FILE *out = freopen("otp_enc_missing_in", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	ck_assert_int_eq(fcrypt_main(9, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("otp_enc_missing_in", expected, strlen(expected));
	remove("otp_enc_missing_in");
}

END_TEST START_TEST(otp_decrypt_missing_input)
{
	char *argv[] =
	    { "fcrypt", "-d", "--key", "otp-dec-missing-in-key", "--cipher",
	 "otp", "--in", "missing-in-dec", "--out", "otp-res", NULL };
	const char expected[] = "failed to open input file\n";

	FILE *fp = fopen("otp-dec-missing-in-key", "wb");
	ck_assert_ptr_nonnull(fp);
	fclose(fp);

	FILE *out = freopen("otp_dec_missing_in", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	ck_assert_int_eq(fcrypt_main(10, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("otp_dec_missing_in", expected, strlen(expected));
	remove("otp_dec_missing_in");
	remove("otp-dec-missing-in-key");
}

END_TEST START_TEST(otp_decrypt_missing_key)
{
	char *argv[] =
	    { "fcrypt", "-d", "--key", "missing-key-dec-key", "--cipher", "otp",
	 "--in", "missing-key-dec-in", "--out", "otp-res", NULL };
	const char expected[] = "failed to open key file\n";

	FILE *fp = fopen("missing-key-dec-in", "wb");
	ck_assert_ptr_nonnull(fp);
	fclose(fp);

	FILE *out = freopen("otp_dec_missing_key", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	ck_assert_int_eq(fcrypt_main(10, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("otp_dec_missing_key", expected, strlen(expected));
	remove("otp_dec_missing_key");
	remove("missing-key-dec-in");
}

END_TEST START_TEST(otp_decrypt_shorter_key)
{
	char *argv[] =
	    { "fcrypt", "-d", "--key", "otp-short-key-key", "--cipher", "otp",
	 "--in", "otp-short-key-in", "--out", "otp-short-key-out", NULL };
	const char expected[] =
	    "key and input file are not of the same length\n";

	FILE *out = freopen("otp_dec_shorter_key", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	rand_file("otp-short-key-key", BUFSIZ);
	rand_file("otp-short-key-in", BUFSIZ + 1);

	ck_assert_int_eq(fcrypt_main(10, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("otp_dec_shorter_key", expected, strlen(expected));
	remove("otp-short-key-key");
	remove("otp-short-key-out");
	remove("otp-short-key-in");
	remove("otp_dec_shorter_key");
}

END_TEST START_TEST(otp_decrypt_shorter_input)
{
	char *argv[] =
	    { "fcrypt", "-d", "--key", "otp-short-in-key", "--cipher", "otp",
	 "--in", "otp-short-in-in", "--out", "otp-short-in-out", NULL };
	const char expected[] =
	    "key and input file are not of the same length\n";

	FILE *out = freopen("otp_dec_shorter_input", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	rand_file("otp-short-in-key", BUFSIZ + 3);
	rand_file("otp-short-in-in", BUFSIZ);

	ck_assert_int_eq(fcrypt_main(10, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("otp_dec_shorter_input", expected, strlen(expected));
	remove("otp-short-in-key");
	remove("otp-short-in-out");
	remove("otp-short-in-in");
	remove("otp_dec_shorter_input");
}

END_TEST START_TEST(rc4_encrypt_decrypt)
{
	char *argv1[] = { "fcrypt", "--key", "rc4-test-key", "--cipher", "rc4",
		"--in", "rc4-infile", "--out", "rc4-outfile", NULL
	};
	char *argv2[] =
	    { "fcrypt", "-d", "--key", "rc4-test-key", "--cipher", "rc4",
	"--in", "rc4-outfile", "--out", "rc4-res", NULL };

	rand_file("rc4-infile", BUFSIZ * 3 + 123);

	ck_assert_int_eq(fcrypt_main(9, argv1), EXIT_SUCCESS);
	ck_assert_int_eq(fcrypt_main(10, argv2), EXIT_SUCCESS);

	compare_files("otp-res", "rc4-infile");
	remove("rc4-infile");
	remove("rc4-outfile");
	remove("rc4-res");
}

END_TEST START_TEST(rc4_encrypt_missing_input)
{
	char *argv[] = { "fcrypt", "--key", "rc4-test-key", "--cipher", "rc4",
		"--in", "missing-in-enc", "--out", "rc4-outfile", NULL
	};
	const char expected[] = "failed to open input file\n";

	FILE *out = freopen("rc4_enc_missing_in", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	ck_assert_int_eq(fcrypt_main(9, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("rc4_enc_missing_in", expected, strlen(expected));
	remove("rc4_enc_missing_in");
}

END_TEST START_TEST(rc4_decrypt_missing_input)
{
	char *argv[] =
	    { "fcrypt", "-d", "--key", "rc4-test-key", "--cipher", "rc4",
	 "--in", "missing-in-dec", "--out", "otp-res", NULL };
	const char expected[] = "failed to open input file\n";

	FILE *out = freopen("rc4_dec_missing_in", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	ck_assert_int_eq(fcrypt_main(10, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("rc4_dec_missing_in", expected, strlen(expected));
	remove("rc4_dec_missing_in");
}

END_TEST START_TEST(des_encrypt_decrypt_ecb)
{
	char *argv1[] =
	    { "fcrypt", "--key", "des-ecb-key", "--cipher", "des", "-m", "ecb",
		"--in", "des-ecb-in", "--out", "des-ecb-out", NULL
	};
	char *argv2[] =
	    { "fcrypt", "-d", "--key", "des-ecb-key", "--cipher", "des", "--in",
	"des-ecb-out", "--out", "des-ecb-res", "-m", "ecb", NULL };

	rand_file("des-ecb-in", BUFSIZ * 3 + 123);

	ck_assert_int_eq(fcrypt_main(11, argv1), EXIT_SUCCESS);
	ck_assert_int_eq(fcrypt_main(12, argv2), EXIT_SUCCESS);

	compare_files("des-ecb-in", "des-ecb-res");
	remove("des-ecb-key");
	remove("des-ecb-in");
	remove("des-ecb-out");
	remove("des-ecb-res");
}

END_TEST START_TEST(des_encrypt_decrypt_cbc)
{
	char *argv1[] =
	    { "fcrypt", "--key", "des-cbc-key", "--cipher", "des", "-m", "cbc",
		"--in", "des-cbc-in", "--out", "des-cbc-out", NULL
	};
	char *argv2[] =
	    { "fcrypt", "-d", "--key", "des-cbc-key", "--cipher", "des", "--in",
	"des-cbc-out", "--out", "des-cbc-res", "-m", "cbc", NULL };

	rand_file("des-cbc-in", BUFSIZ * 3 + 123);

	ck_assert_int_eq(fcrypt_main(11, argv1), EXIT_SUCCESS);
	ck_assert_int_eq(fcrypt_main(12, argv2), EXIT_SUCCESS);

	compare_files("des-cbc-in", "des-cbc-res");
	remove("des-cbc-key");
	remove("des-cbc-in");
	remove("des-cbc-out");
	remove("des-cbc-res");
}

END_TEST START_TEST(des_encrypt_decrypt_cfb)
{
	char *argv1[] =
	    { "fcrypt", "--key", "des-cfb-key", "--cipher", "des", "-m", "cfb",
		"--in", "des-cfb-in", "--out", "des-cfb-out", NULL
	};
	char *argv2[] =
	    { "fcrypt", "-d", "--key", "des-cfb-key", "--cipher", "des", "--in",
	"des-cfb-out", "--out", "des-cfb-res", "-m", "cfb", NULL };

	rand_file("des-cfb-in", BUFSIZ * 3 + 123);

	ck_assert_int_eq(fcrypt_main(11, argv1), EXIT_SUCCESS);
	ck_assert_int_eq(fcrypt_main(12, argv2), EXIT_SUCCESS);

	compare_files("des-cfb-in", "des-cfb-res");
	remove("des-cfb-key");
	remove("des-cfb-in");
	remove("des-cfb-out");
	remove("des-cfb-res");
}

END_TEST START_TEST(des_encrypt_decrypt_ofb)
{
	char *argv1[] =
	    { "fcrypt", "--key", "des-ofb-key", "--cipher", "des", "-m", "ofb",
		"--in", "des-ofb-in", "--out", "des-ofb-out", NULL
	};
	char *argv2[] =
	    { "fcrypt", "-d", "--key", "des-ofb-key", "--cipher", "des", "--in",
	"des-ofb-out", "--out", "des-ofb-res", "-m", "ofb", NULL };

	rand_file("des-ofb-in", BUFSIZ * 3 + 123);

	ck_assert_int_eq(fcrypt_main(11, argv1), EXIT_SUCCESS);
	ck_assert_int_eq(fcrypt_main(12, argv2), EXIT_SUCCESS);

	compare_files("des-ofb-in", "des-ofb-res");
	remove("des-ofb-key");
	remove("des-ofb-in");
	remove("des-ofb-out");
	remove("des-ofb-res");
}

END_TEST START_TEST(des_cbc_missing_iv)
{
	char *argv[] =
	    { "fcrypt", "-d", "--key", "des-cbc-missing-iv-key", "--cipher",
	 "des", "--in", "des-cbc-missing-iv-in", "--out",
	 "des-cbc-missing-iv-out", "-m", "cbc", NULL };
	const char expected[] = "failed to read initialization vector\n";

	FILE *out = freopen("des-cbc-missing-iv-err", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	rand_file("des-cbc-missing-iv-key", des_keysz);
	rand_file("des-cbc-missing-iv-in", des_blksz - 1);

	ck_assert_int_eq(fcrypt_main(12, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("des-cbc-missing-iv-err", expected, strlen(expected));
	remove("des-cbc-missing-iv-out");
	remove("des-cbc-missing-iv-key");
	remove("des-cbc-missing-iv-in");
	remove("des-cbc-missing-iv-err");
}

END_TEST START_TEST(des_cfb_missing_iv)
{
	char *argv[] =
	    { "fcrypt", "-d", "--key", "des-cfb-missing-iv-key", "--cipher",
	 "des", "--in", "des-cfb-missing-iv-in", "--out",
	 "des-cfb-missing-iv-out", "-m", "cfb", NULL };
	const char expected[] = "failed to read initialization vector\n";

	FILE *out = freopen("des-cfb-missing-iv-err", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	rand_file("des-cfb-missing-iv-key", des_keysz);
	rand_file("des-cfb-missing-iv-in", des_blksz - 1);

	ck_assert_int_eq(fcrypt_main(12, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("des-cfb-missing-iv-err", expected, strlen(expected));
	remove("des-cfb-missing-iv-out");
	remove("des-cfb-missing-iv-key");
	remove("des-cfb-missing-iv-in");
	remove("des-cfb-missing-iv-err");
}

END_TEST START_TEST(des_ofb_missing_iv)
{
	char *argv[] =
	    { "fcrypt", "-d", "--key", "des-ofb-missing-iv-key", "--cipher",
	 "des", "--in", "des-ofb-missing-iv-in", "--out",
	 "des-ofb-missing-iv-out", "-m", "ofb", NULL };
	const char expected[] = "failed to read initialization vector\n";

	FILE *out = freopen("des-ofb-missing-iv-err", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	rand_file("des-ofb-missing-iv-key", des_keysz);
	rand_file("des-ofb-missing-iv-in", des_blksz - 1);

	ck_assert_int_eq(fcrypt_main(12, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("des-ofb-missing-iv-err", expected, strlen(expected));
	remove("des-ofb-missing-iv-out");
	remove("des-ofb-missing-iv-key");
	remove("des-ofb-missing-iv-in");
	remove("des-ofb-missing-iv-err");
}

END_TEST START_TEST(des_encrypt_missing_input)
{
	char *argv[] =
	    { "fcrypt", "--key", "des-enc-missing-in-key", "--cipher", "des",
		"--in", "des-enc-missing-in-in", "--out",
		    "des-enc-missing-in-out", NULL
	};
	const char expected[] = "failed to open input file\n";

	FILE *out = freopen("des-enc-missing-in-err", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	ck_assert_int_eq(fcrypt_main(9, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("des-enc-missing-in-err", expected, strlen(expected));
	remove("des-enc-missing-in-err");
}

END_TEST START_TEST(des_decrypt_missing_input)
{
	char *argv[] =
	    { "fcrypt", "-d", "--key", "des-dec-missing-in-key", "--cipher",
	 "des", "--in", "des-dec-missing-in-in", "--out",
	 "des-dec-missing-in-out", NULL };
	const char expected[] = "failed to open input file\n";

	rand_file("des-dec-missing-in-key", des_keysz);

	FILE *out = freopen("des-dec-missing-in-err", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	ck_assert_int_eq(fcrypt_main(10, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("des-dec-missing-in-err", expected, strlen(expected));
	remove("des-dec-missing-in-err");
	remove("des-dec-missing-in-key");
}

END_TEST START_TEST(des_decrypt_missing_key)
{
	char *argv[] =
	    { "fcrypt", "-d", "--key", "des-dec-missing-key-key", "--cipher",
	 "des", "--in", "des-dec-missing-key-in", "--out",
	 "des-dec-missing-key-out", NULL };
	const char expected[] = "failed to initialize block cipher\n";

	FILE *fp = fopen("des-dec-missing-key-in", "wb");
	ck_assert_ptr_nonnull(fp);
	fclose(fp);

	FILE *out = freopen("des-dec-missing-key-err", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	ck_assert_int_eq(fcrypt_main(10, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("des-dec-missing-key-err", expected, strlen(expected));
	remove("des-dec-missing-key-in");
	remove("des-dec-missing-key-err");
}

END_TEST START_TEST(des_decrypt_empty_key)
{
	char *argv[] =
	    { "fcrypt", "-d", "--key", "des-dec-empty-key-key", "--cipher",
	 "des", "--in", "des-dec-empty-key-in", "--out",
	 "des-dec-empty-key-out", NULL };
	const char expected[] = "failed to initialize block cipher\n";

	rand_file("des-dec-empty-key-in", des_blksz * 10);

	FILE *fp = fopen("des-dec-empty-key-key", "wb");
	ck_assert_ptr_nonnull(fp);
	fclose(fp);

	FILE *out = freopen("des-dec-empty-key-err", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	ck_assert_int_eq(fcrypt_main(10, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("des-dec-empty-key-err", expected, strlen(expected));
	remove("des-dec-empty-key-in");
	remove("des-dec-empty-key-key");
	remove("des-dec-empty-key-err");
}

END_TEST START_TEST(des_invalid_decrypt)
{
	char *argv[] =
	    { "fcrypt", "-d", "--key", "des-invalid-dec-key", "--cipher", "des",
	 "--in", "des-invalid-dec-in", "--out", "des-invalid-dec-out", NULL };
	const char expected[] = "invalid file for decryption\n";

	rand_file("des-invalid-dec-in", des_blksz * 10 - 2);
	rand_file("des-invalid-dec-key", des_keysz);

	FILE *out = freopen("des-invalid-dec-err", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	ck_assert_int_eq(fcrypt_main(10, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("des-invalid-dec-err", expected, strlen(expected));
	remove("des-invalid-dec-in");
	remove("des-invalid-dec-out");
	remove("des-invalid-dec-key");
	remove("des-invalid-dec-err");
}

END_TEST START_TEST(tdea_encrypt_decrypt_ecb)
{
	char *argv1[] =
	    { "fcrypt", "--key", "tdea-ecb-key", "--cipher", "tdea", "-m",
	"ecb",
		"--in", "tdea-ecb-in", "--out", "tdea-ecb-out", NULL
	};
	char *argv2[] =
	    { "fcrypt", "-d", "--key", "tdea-ecb-key", "--cipher", "tdea",
	"--in", "tdea-ecb-out", "--out", "tdea-ecb-res", "-m", "ecb", NULL };

	rand_file("tdea-ecb-in", 100);

	ck_assert_int_eq(fcrypt_main(11, argv1), EXIT_SUCCESS);
	ck_assert_int_eq(fcrypt_main(12, argv2), EXIT_SUCCESS);

	compare_files("tdea-ecb-in", "tdea-ecb-res");
	remove("tdea-ecb-key");
	remove("tdea-ecb-in");
	remove("tdea-ecb-out");
	remove("tdea-ecb-res");
}

END_TEST START_TEST(tdea_encrypt_decrypt_cbc)
{
	char *argv1[] =
	    { "fcrypt", "--key", "tdea-cbc-key", "--cipher", "tdea", "-m",
	"cbc",
		"--in", "tdea-cbc-in", "--out", "tdea-cbc-out", NULL
	};
	char *argv2[] =
	    { "fcrypt", "-d", "--key", "tdea-cbc-key", "--cipher", "tdea",
	"--in", "tdea-cbc-out", "--out", "tdea-cbc-res", "-m", "cbc", NULL };

	rand_file("tdea-cbc-in", 100);

	ck_assert_int_eq(fcrypt_main(11, argv1), EXIT_SUCCESS);
	ck_assert_int_eq(fcrypt_main(12, argv2), EXIT_SUCCESS);

	compare_files("tdea-cbc-in", "tdea-cbc-res");
	remove("tdea-cbc-key");
	remove("tdea-cbc-in");
	remove("tdea-cbc-out");
	remove("tdea-cbc-res");
}

END_TEST START_TEST(tdea_encrypt_decrypt_cfb)
{
	char *argv1[] =
	    { "fcrypt", "--key", "tdea-cfb-key", "--cipher", "tdea", "-m",
	"cfb",
		"--in", "tdea-cfb-in", "--out", "tdea-cfb-out", NULL
	};
	char *argv2[] =
	    { "fcrypt", "-d", "--key", "tdea-cfb-key", "--cipher", "tdea",
	"--in", "tdea-cfb-out", "--out", "tdea-cfb-res", "-m", "cfb", NULL };

	rand_file("tdea-cfb-in", 100);

	ck_assert_int_eq(fcrypt_main(11, argv1), EXIT_SUCCESS);
	ck_assert_int_eq(fcrypt_main(12, argv2), EXIT_SUCCESS);

	compare_files("tdea-cfb-in", "tdea-cfb-res");
	remove("tdea-cfb-key");
	remove("tdea-cfb-in");
	remove("tdea-cfb-out");
	remove("tdea-cfb-res");
}

END_TEST START_TEST(tdea_encrypt_decrypt_ofb)
{
	char *argv1[] =
	    { "fcrypt", "--key", "tdea-ofb-key", "--cipher", "tdea", "-m",
	"ofb",
		"--in", "tdea-ofb-in", "--out", "tdea-ofb-out", NULL
	};
	char *argv2[] =
	    { "fcrypt", "-d", "--key", "tdea-ofb-key", "--cipher", "tdea",
	"--in", "tdea-ofb-out", "--out", "tdea-ofb-res", "-m", "ofb", NULL };

	rand_file("tdea-ofb-in", 100);

	ck_assert_int_eq(fcrypt_main(11, argv1), EXIT_SUCCESS);
	ck_assert_int_eq(fcrypt_main(12, argv2), EXIT_SUCCESS);

	compare_files("tdea-ofb-in", "tdea-ofb-res");
	remove("tdea-ofb-key");
	remove("tdea-ofb-in");
	remove("tdea-ofb-out");
	remove("tdea-ofb-res");
}

END_TEST START_TEST(tdea_cbc_missing_iv)
{
	char *argv[] =
	    { "fcrypt", "-d", "--key", "tdea-cbc-missing-iv-key", "--cipher",
	 "tdea", "--in", "tdea-cbc-missing-iv-in", "--out",
	 "tdea-cbc-missing-iv-out", "-m", "cbc", NULL };
	const char expected[] = "failed to read initialization vector\n";

	FILE *out = freopen("tdea-cbc-missing-iv-err", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	rand_file("tdea-cbc-missing-iv-key", tdea_keysz);
	rand_file("tdea-cbc-missing-iv-in", tdea_blksz - 1);

	ck_assert_int_eq(fcrypt_main(12, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("tdea-cbc-missing-iv-err", expected, strlen(expected));
	remove("tdea-cbc-missing-iv-out");
	remove("tdea-cbc-missing-iv-key");
	remove("tdea-cbc-missing-iv-in");
	remove("tdea-cbc-missing-iv-err");
}

END_TEST START_TEST(tdea_cfb_missing_iv)
{
	char *argv[] =
	    { "fcrypt", "-d", "--key", "tdea-cfb-missing-iv-key", "--cipher",
	 "tdea", "--in", "tdea-cfb-missing-iv-in", "--out",
	 "tdea-cfb-missing-iv-out", "-m", "cfb", NULL };
	const char expected[] = "failed to read initialization vector\n";

	FILE *out = freopen("tdea-cfb-missing-iv-err", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	rand_file("tdea-cfb-missing-iv-key", tdea_keysz);
	rand_file("tdea-cfb-missing-iv-in", tdea_blksz - 1);

	ck_assert_int_eq(fcrypt_main(12, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("tdea-cfb-missing-iv-err", expected, strlen(expected));
	remove("tdea-cfb-missing-iv-out");
	remove("tdea-cfb-missing-iv-key");
	remove("tdea-cfb-missing-iv-in");
	remove("tdea-cfb-missing-iv-err");
}

END_TEST START_TEST(tdea_ofb_missing_iv)
{
	char *argv[] =
	    { "fcrypt", "-d", "--key", "tdea-ofb-missing-iv-key", "--cipher",
	 "tdea", "--in", "tdea-ofb-missing-iv-in", "--out",
	 "tdea-ofb-missing-iv-out", "-m", "ofb", NULL };
	const char expected[] = "failed to read initialization vector\n";

	FILE *out = freopen("tdea-ofb-missing-iv-err", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	rand_file("tdea-ofb-missing-iv-key", tdea_keysz);
	rand_file("tdea-ofb-missing-iv-in", tdea_blksz - 1);

	ck_assert_int_eq(fcrypt_main(12, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("tdea-ofb-missing-iv-err", expected, strlen(expected));
	remove("tdea-ofb-missing-iv-out");
	remove("tdea-ofb-missing-iv-key");
	remove("tdea-ofb-missing-iv-in");
	remove("tdea-ofb-missing-iv-err");
}

END_TEST START_TEST(tdea_encrypt_missing_input)
{
	char *argv[] =
	    { "fcrypt", "--key", "tdea-enc-missing-in-key", "--cipher", "tdea",
		"--in", "tdea-enc-missing-in-in", "--out",
		    "tdea-enc-missing-in-out", NULL
	};
	const char expected[] = "failed to open input file\n";

	FILE *out = freopen("tdea-enc-missing-in-err", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	ck_assert_int_eq(fcrypt_main(9, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("tdea-enc-missing-in-err", expected, strlen(expected));
	remove("tdea-enc-missing-in-err");
}

END_TEST START_TEST(tdea_decrypt_missing_input)
{
	char *argv[] =
	    { "fcrypt", "-d", "--key", "tdea-dec-missing-in-key", "--cipher",
	 "tdea", "--in", "tdea-dec-missing-in-in", "--out",
	 "tdea-dec-missing-in-out", NULL };
	const char expected[] = "failed to open input file\n";

	rand_file("tdea-dec-missing-in-key", tdea_keysz);

	FILE *out = freopen("tdea-dec-missing-in-err", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	ck_assert_int_eq(fcrypt_main(10, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("tdea-dec-missing-in-err", expected, strlen(expected));
	remove("tdea-dec-missing-in-err");
	remove("tdea-dec-missing-in-key");
}

END_TEST START_TEST(tdea_decrypt_missing_key)
{
	char *argv[] =
	    { "fcrypt", "-d", "--key", "tdea-dec-missing-key-key", "--cipher",
	 "tdea", "--in", "tdea-dec-missing-key-in", "--out",
	 "tdea-dec-missing-key-out", NULL };
	const char expected[] = "failed to initialize block cipher\n";

	FILE *fp = fopen("tdea-dec-missing-key-in", "wb");
	ck_assert_ptr_nonnull(fp);
	fclose(fp);

	FILE *out = freopen("tdea-dec-missing-key-err", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	ck_assert_int_eq(fcrypt_main(10, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("tdea-dec-missing-key-err", expected,
			 strlen(expected));
	remove("tdea-dec-missing-key-in");
	remove("tdea-dec-missing-key-err");
}

END_TEST START_TEST(tdea_decrypt_empty_key)
{
	char *argv[] =
	    { "fcrypt", "-d", "--key", "tdea-dec-empty-key-key", "--cipher",
	 "tdea", "--in", "tdea-dec-empty-key-in", "--out",
	 "tdea-dec-empty-key-out", NULL };
	const char expected[] = "failed to initialize block cipher\n";

	rand_file("tdea-dec-empty-key-in", tdea_blksz * 10);

	FILE *fp = fopen("tdea-dec-empty-key-key", "wb");
	ck_assert_ptr_nonnull(fp);
	fclose(fp);

	FILE *out = freopen("tdea-dec-empty-key-err", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	ck_assert_int_eq(fcrypt_main(10, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("tdea-dec-empty-key-err", expected, strlen(expected));
	remove("tdea-dec-empty-key-in");
	remove("tdea-dec-empty-key-key");
	remove("tdea-dec-empty-key-err");
}

END_TEST START_TEST(tdea_invalid_decrypt)
{
	char *argv[] =
	    { "fcrypt", "-d", "--key", "tdea-invalid-dec-key", "--cipher",
	 "tdea", "--in", "tdea-invalid-dec-in", "--out", "tdea-invalid-dec-out",
	 NULL };
	const char expected[] = "invalid file for decryption\n";

	rand_file("tdea-invalid-dec-in", tdea_blksz * 10 - 2);
	rand_file("tdea-invalid-dec-key", tdea_keysz);

	FILE *out = freopen("tdea-invalid-dec-err", "wb", stdout);
	ck_assert_ptr_nonnull(out);

	ck_assert_int_eq(fcrypt_main(10, argv), EXIT_FAILURE);
	fclose(out);

	compare_file_str("tdea-invalid-dec-err", expected, strlen(expected));
	remove("tdea-invalid-dec-in");
	remove("tdea-invalid-dec-out");
	remove("tdea-invalid-dec-key");
	remove("tdea-invalid-dec-err");
}

END_TEST Suite * hashset_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("fcrypt");

	tc = tcase_create("flags");
	tcase_add_test(tc, help_page_long);
	tcase_add_test(tc, help_page_short);
	tcase_add_test(tc, invalid_flag1);
	tcase_add_test(tc, invalid_flag2);
	tcase_add_test(tc, missing_key);
	tcase_add_test(tc, missing_cipher);
	tcase_add_test(tc, missing_in);
	tcase_add_test(tc, missing_out);
	tcase_add_test(tc, invalid_mode);
	tcase_add_test(tc, invalid_cipher);
	tcase_add_test(tc, encrypt_no_mode);
	tcase_add_test(tc, decrypt_no_mode);
	suite_add_tcase(s, tc);

	tc = tcase_create("otp");
	tcase_add_test(tc, otp_encrypt_decrypt);
	tcase_add_test(tc, otp_encrypt_missing_input);
	tcase_add_test(tc, otp_decrypt_missing_input);
	tcase_add_test(tc, otp_decrypt_missing_key);
	tcase_add_test(tc, otp_decrypt_shorter_key);
	tcase_add_test(tc, otp_decrypt_shorter_input);
	suite_add_tcase(s, tc);

	tc = tcase_create("rc4");
	tcase_add_test(tc, rc4_encrypt_decrypt);
	tcase_add_test(tc, rc4_encrypt_missing_input);
	tcase_add_test(tc, rc4_decrypt_missing_input);
	suite_add_tcase(s, tc);

	tc = tcase_create("des");
	tcase_add_test(tc, des_encrypt_decrypt_ecb);
	tcase_add_test(tc, des_encrypt_decrypt_cbc);
	tcase_add_test(tc, des_encrypt_decrypt_cfb);
	tcase_add_test(tc, des_encrypt_decrypt_ofb);

	tcase_add_test(tc, des_cbc_missing_iv);
	tcase_add_test(tc, des_cfb_missing_iv);
	tcase_add_test(tc, des_ofb_missing_iv);

	tcase_add_test(tc, des_encrypt_missing_input);
	tcase_add_test(tc, des_decrypt_missing_input);
	tcase_add_test(tc, des_decrypt_missing_key);
	tcase_add_test(tc, des_decrypt_empty_key);
	tcase_add_test(tc, des_invalid_decrypt);
	suite_add_tcase(s, tc);

	tc = tcase_create("tdea");
	tcase_add_test(tc, tdea_encrypt_decrypt_ecb);
	tcase_add_test(tc, tdea_encrypt_decrypt_cbc);
	tcase_add_test(tc, tdea_encrypt_decrypt_cfb);
	tcase_add_test(tc, tdea_encrypt_decrypt_ofb);

	tcase_add_test(tc, tdea_cbc_missing_iv);
	tcase_add_test(tc, tdea_cfb_missing_iv);
	tcase_add_test(tc, tdea_ofb_missing_iv);

	tcase_add_test(tc, tdea_encrypt_missing_input);
	tcase_add_test(tc, tdea_decrypt_missing_input);
	tcase_add_test(tc, tdea_decrypt_missing_key);
	tcase_add_test(tc, tdea_decrypt_empty_key);
	tcase_add_test(tc, tdea_invalid_decrypt);
	suite_add_tcase(s, tc);

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

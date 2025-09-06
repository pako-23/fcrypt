#include <crypt/des.h>
#include <crypt/block.h>
#include <crypt/rand.h>
#include <crypt/stream.h>
#include <fcrypt.h>
#include <getopt.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HELP_FMT                                                               \
  "Usage: %s [options]\n\n"                                                    \
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

static struct option cli_options[] = {
	{"mode", required_argument, 0, 'm'},
	{"cipher", required_argument, 0, 'c'},
	{"decrypt", no_argument, 0, 'd'},
	{"in", required_argument, 0, 'i'},
	{"out", required_argument, 0, 'o'},
	{"key", required_argument, 0, 'k'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

static const char *valid_modes[] = { "ecb", "cbc", "cfb", "ofb", NULL };
static const char *valid_ciphers[] = { "otp", "rc4", "des", "tdea", NULL };

static int strinset(const char *str, const char *set[])
{
	const char **p;

	for (p = set; *p; ++p)
		if (strcmp(str, *p) == 0)
			return 1;

	return 0;
}

static int otp_file_enc(const char *ifile, const char *ofile, const char *kfile)
{
	FILE *istream, *ostream, *kstream;
	int error = EXIT_SUCCESS;
	uint8_t input[4096], key[4096];
	size_t nread;

	istream = fopen(ifile, "rb");
	if (istream == NULL) {
		printf("failed to open input file\n");
		error = EXIT_FAILURE;
		goto out;
	}

	ostream = fopen(ofile, "wb");
	if (ostream == NULL) {
		printf("failed to create output file\n");
		error = EXIT_FAILURE;
		goto istream_out;
	}

	kstream = fopen(kfile, "wb");
	if (kstream == NULL) {
		printf("failed to create key file\n");
		error = EXIT_FAILURE;
		goto ostream_out;
	}

	while ((nread = fread(input, 1, sizeof(input), istream)) > 0) {
		cr_rand_bytes(key, nread);
		cr_otp(input, key, input, nread);

		if (fwrite(input, 1, nread, ostream) != nread) {
			printf("failed to write into output file\n");
			error = EXIT_FAILURE;
			break;
		}

		if (fwrite(key, 1, nread, kstream) != nread) {
			printf("failed to write into key file\n");
			error = EXIT_FAILURE;
			break;
		}
	}

	if (ferror(istream)) {
		printf("failed to read from input file\n");
		error = EXIT_FAILURE;
	}

	fclose(kstream);
 ostream_out:
	fclose(ostream);
 istream_out:
	fclose(istream);
 out:
	return error;
}

static int otp_file_dec(const char *ifile, const char *ofile, const char *kfile)
{
	FILE *istream, *ostream, *kstream;
	int error = EXIT_SUCCESS;
	uint8_t input[4096], key[4096];
	size_t nreadi, nreadk;

	istream = fopen(ifile, "rb");
	if (istream == NULL) {
		printf("failed to open input file\n");
		error = EXIT_FAILURE;
		goto out;
	}

	ostream = fopen(ofile, "wb");
	if (ostream == NULL) {
		printf("failed to create output file\n");
		error = EXIT_FAILURE;
		goto istream_out;
	}

	kstream = fopen(kfile, "rb");
	if (kstream == NULL) {
		printf("failed to open key file\n");
		error = EXIT_FAILURE;
		goto ostream_out;
	}

	while (1) {
		nreadi = fread(input, 1, sizeof(input), istream);
		nreadk = fread(key, 1, sizeof(key), kstream);

		if (nreadi != nreadk) {
			printf
			    ("key and input file are not of the same length\n");
			error = EXIT_FAILURE;
			break;
		}
		if (nreadi == 0)
			break;

		cr_otp(input, key, input, nreadi);

		if (fwrite(input, 1, nreadi, ostream) != nreadi) {
			printf("failed to write decrypted data\n");
			error = EXIT_FAILURE;
			break;
		}
	}

	if (ferror(istream)) {
		printf("failed to read from input file\n");
		error = EXIT_FAILURE;
	}

	if (ferror(ostream)) {
		printf("failed to read from key file\n");
		error = EXIT_FAILURE;
	}

	fclose(kstream);
 ostream_out:
	fclose(ostream);
 istream_out:
	fclose(istream);
 out:
	return error;
}

static int rc4_file_run(const char *ifile, const char *ofile, const char *key)
{
	FILE *istream, *ostream;
	int error = 0;
	uint8_t input[4096], output[4096];
	size_t nread;
	struct cr_rc4_s *cipher;
	size_t klen = strlen(key);

	istream = fopen(ifile, "rb");
	if (istream == NULL) {
		printf("failed to open input file\n");
		error = EXIT_FAILURE;
		goto out;
	}

	ostream = fopen(ofile, "wb");
	if (ostream == NULL) {
		printf("failed to create output file\n");
		error = EXIT_FAILURE;
		goto istream_out;
	}

	cipher = cr_rc4_new((const uint8_t *)key, klen);
	if (cipher == NULL) {
		printf("failed to setup RC4 cipher\n");
		error = EXIT_FAILURE;
		goto ostream_out;
	}

	while ((nread = fread(input, 1, sizeof(input), istream)) > 0) {
		cr_rc4_encrypt(cipher, input, nread, output);
		if (fwrite(output, 1, nread, ostream) != nread) {
			printf("failed to write into output file\n");
			error = EXIT_FAILURE;
			break;
		}
	}

	if (ferror(istream)) {
		printf("failed to read from input file\n");
		error = EXIT_FAILURE;
	}

	cr_rc4_destroy(cipher);
 ostream_out:
	fclose(ostream);
 istream_out:
	fclose(istream);
 out:
	return error;
}

static int generate_key(const char *fname, uint8_t *key, size_t len)
{
	FILE *fp;
	int error = 0;

	fp = fopen(fname, "wb");
	if (fp == NULL) {
		error = -1;
		goto out;
	}

	error = cr_rand_bytes(key, len);
	if (error == 0) {
		if (fwrite(key, 1, len, fp) != len)
			error = -1;
	}

	fclose(fp);
 out:
	return error;
}

static int read_key(const char *fname, uint8_t *key, size_t len)
{
	FILE *fp;
	int error = 0;

	fp = fopen(fname, "rb");
	if (fp == NULL) {
		error = -1;
		goto out;
	}

	if (fread(key, 1, len, fp) != len)
		error = -1;

	fclose(fp);
 out:
	return error;
}

static struct cr_bcphr_s *get_block_cipher(const char *modestr,
					   const char *ciphrstr,
					   int (*keygen)(const char *,
							 uint8_t *, size_t),
					   const char *kfname)
{
	enum cr_bcphr_mode mode;
	size_t keysz;
	uint8_t *key;
	struct cr_bcphr_s *(*constructor) (const uint8_t *, enum cr_bcphr_mode);
	struct cr_bcphr_s *cipher;

	if (strcmp(modestr, "ecb") == 0)
		mode = CR_BCPHR_ECB_MODE;
	else if (strcmp(modestr, "cbc") == 0)
		mode = CR_BCPHR_CBC_MODE;
	else if (strcmp(modestr, "cfb") == 0)
		mode = CR_BCPHR_CFB_MODE;
	else if (strcmp(modestr, "ofb") == 0)
		mode = CR_BCPHR_OFB_MODE;

	if (strcmp(ciphrstr, "des") == 0) {
		keysz = des_keysz;
		constructor = cr_bcphr_des;
	} else {
		keysz = tdea_keysz;
		constructor = cr_bcphr_tdea;
	}

	key = malloc(keysz);
	if (key == NULL)
		return NULL;

	if (keygen(kfname, key, keysz) != 0) {
		free(key);
		return NULL;
	}

	cipher = constructor(key, mode);
	free(key);

	return cipher;
}

static int block_file_enc(const char *ifile, const char *ofile,
			  const char *kfile, const char *mode,
			  const char *cname)
{
	FILE *istream, *ostream;
	int error = EXIT_SUCCESS;
	uint8_t input[4096], output[4096];
	size_t nread, nenc, blksz;
	struct cr_bcphr_s *cipher =
	    get_block_cipher(mode, cname, generate_key, kfile);

	if (cipher == NULL) {
		printf("failed to initialize block cipher\n");
		error = EXIT_FAILURE;
		goto out;
	}

	blksz = cr_bcphr_block_size(cipher);
	istream = fopen(ifile, "rb");
	if (istream == NULL) {
		printf("failed to open input file\n");
		error = EXIT_FAILURE;
		goto cipher_out;
	}

	ostream = fopen(ofile, "wb");
	if (ostream == NULL) {
		printf("failed to create output file\n");
		error = EXIT_FAILURE;
		goto istream_out;
	}

	if (cr_bcphr_get_mode(cipher) != CR_BCPHR_ECB_MODE) {
		cr_bcphr_get_iv(cipher, output);

		if (fwrite(output, 1, blksz, ostream) != blksz) {
			printf("failed to write initialization vector\n");
			error = EXIT_FAILURE;
			goto ostream_out;
		}
	}

	while (1) {
		nread = fread(input, 1, sizeof(input), istream);
		if (nread == 0)
			break;

		nenc = cr_bcphr_encrypt(cipher, input, nread, output);
		if (fwrite(output, 1, nenc, ostream) != nenc) {
			printf("failed to write encrypted data\n");
			error = EXIT_FAILURE;
			break;
		}
	}

	if (ferror(istream)) {
		printf("failed to read from input file\n");
		error = EXIT_FAILURE;
		goto ostream_out;
	}

	cr_bcphr_encrypt_finalize(cipher, output);
	if (fwrite(output, 1, blksz, ostream) != blksz) {
		printf("failed to write encrypted data\n");
		error = EXIT_FAILURE;
	}

 ostream_out:
	fclose(ostream);
 istream_out:
	fclose(istream);
 cipher_out:
	cr_bcphr_destroy(cipher);
 out:
	return error;
}

static int block_file_dec(const char *ifile, const char *ofile,
			  const char *kfile, const char *mode,
			  const char *cname)
{
	FILE *istream, *ostream;
	int error = EXIT_SUCCESS;
	uint8_t input[4096], output[4096];
	size_t nread, blksz;
	ssize_t ndec;
	struct cr_bcphr_s *cipher =
	    get_block_cipher(mode, cname, read_key, kfile);

	if (cipher == NULL) {
		printf("failed to initialize block cipher\n");
		error = EXIT_FAILURE;
		goto out;
	}

	blksz = cr_bcphr_block_size(cipher);
	istream = fopen(ifile, "rb");
	if (istream == NULL) {
		printf("failed to open input file\n");
		error = EXIT_FAILURE;
		goto cipher_out;
	}

	ostream = fopen(ofile, "wb");
	if (ostream == NULL) {
		printf("failed to create output file\n");
		error = EXIT_FAILURE;
		goto istream_out;
	}

	if (cr_bcphr_get_mode(cipher) != CR_BCPHR_ECB_MODE) {
		if (fread(input, 1, blksz, istream) != blksz) {
			printf("failed to read initialization vector\n");
			error = EXIT_FAILURE;
			goto ostream_out;
		}

		cr_bcphr_set_iv(cipher, input);
	}

	while (1) {
		nread = fread(input, 1, sizeof(input), istream);
		if (nread == 0)
			break;

		ndec = cr_bcphr_decrypt(cipher, input, nread, output);
		if (fwrite(output, 1, ndec, ostream) != ndec) {
			printf("failed to write decrypted data 1\n");
			error = EXIT_FAILURE;
			break;
		}
	}

	if (ferror(istream)) {
		printf("failed to read from input file\n");
		error = EXIT_FAILURE;
		goto ostream_out;
	}

	ndec = cr_bcphr_decrypt_finalize(cipher, output);
	if (ndec < 0) {
		printf("invalid file for decryption\n");
		error = EXIT_FAILURE;
		goto ostream_out;
	}

	if (fwrite(output, 1, ndec, ostream) != ndec) {
		printf("failed to write decrypted data 2\n");
		error = EXIT_FAILURE;
	}

 ostream_out:
	fclose(ostream);
 istream_out:
	fclose(istream);
 cipher_out:
	cr_bcphr_destroy(cipher);
 out:
	return error;
}

int fcrypt_main(int argc, char **argv)
{
	const char *mode = "cbc";
	const char *cipher = NULL;
	const char *key = NULL;
	const char *in = NULL;
	const char *out = NULL;
	int decrypt = 0;
	int opt, opt_index;

	optind = 1;
	opterr = 0;
	while (optind < argc) {
		opt =
		    getopt_long(argc, argv, "m:c:i:o:k:hd", cli_options,
				&opt_index);
		if (opt < 0) {
			printf("unknown option: %s\n", argv[optind]);
			goto out;
		}

		switch (opt) {
		case 'm':
			mode = optarg;
			break;

		case 'c':
			cipher = optarg;
			break;

		case 'd':
			decrypt = 1;
			break;

		case 'i':
			in = optarg;
			break;

		case 'k':
			key = optarg;
			break;

		case 'o':
			out = optarg;
			break;

		case 'h':
			printf(HELP_FMT, argv[0]);
			return EXIT_SUCCESS;

		default:
			printf("unknown option: %s\n", argv[optind - 1]);
			goto out;
		}
	}

	if (key == NULL) {
		printf("a key/keyfile is required\n");
		goto out;
	} else if (in == NULL) {
		printf("an input file is required\n");
		goto out;
	} else if (out == NULL) {
		printf("an output file is required\n");
		goto out;
	} else if (cipher == NULL) {
		printf("a cipher is required\n");
		goto out;
	} else if (!strinset(mode, valid_modes)) {
		printf("unknown operation mode: %s\n", mode);
		goto out;
	} else if (!strinset(cipher, valid_ciphers)) {
		printf("unknown cipher: %s\n", cipher);
		goto out;
	}

	if (decrypt == 0) {
		if (strcmp(cipher, "otp") == 0)
			return otp_file_enc(in, out, key);
		else if (strcmp(cipher, "rc4") == 0)
			return rc4_file_run(in, out, key);
		return block_file_enc(in, out, key, mode, cipher);

	} else {
		if (strcmp(cipher, "otp") == 0)
			return otp_file_dec(in, out, key);
		else if (strcmp(cipher, "rc4") == 0)
			return rc4_file_run(in, out, key);
		return block_file_dec(in, out, key, mode, cipher);
	}

 out:
	printf(HELP_FMT, argv[0]);
	return EXIT_FAILURE;
}

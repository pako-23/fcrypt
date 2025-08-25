#include <crypt/rand.h>
#include <stdio.h>

int cr_rand_bytes(unsigned char *buf, size_t len) {
    FILE *fp;
    int err = 0;

    if (len == 0)
      return 0;

    fp = fopen("/dev/urandom", "rb");
    if (fp == NULL)
      return -1;

    if (fread(buf, 1, len, fp) != len)
        err = -1;

    fclose(fp);
    return err;
}

# One Time Pad
The first cryptosystem we will look at is the one-time pad.  The
one-time pad is a symmetric cyrptosystem that is considered
theoretically unbreakable.  Its security relies on a few simple rules:

 1. The key must be truly random.
 2. The key must be at least the same length as the plaintext.
 3. The key must not be reused.

The core implementation of one-time pad is simple. It consists of the
bitwise XOR between the plaintext and the key. The XOR is a logic
operator having the following truth table:

| A | B | A XOR B |
|:-:|:-:|:-------:|
| 0 | 0 | 0       |
| 0 | 1 | 1       |
| 1 | 0 | 1       |
| 1 | 1 | 0       |


From the truth table, we can notice that A = A XOR B XOR B. Therefore,
the decryption function is the same as the encryption.

In this step, try implementing the `cr_otp` function declared in the
`src/crypt/include/crypt/stream.h` file.  The implementation must be
inserted into the `src/crypt/stream.c` file.  The `cr_otp` function
must compute the one-time pad between `len` bytes of `plain` and `len`
bytes of `key`. I must write the result in `out`.

Once you finished your implementation, the `check_otp` testsuite
should be passing.

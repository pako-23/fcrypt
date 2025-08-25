# Implementing a Cryptographically Secure PRNG
For many of the cryptographic algorithms we will implement, we need a
source random bytes.  However, we cannot use the standard
pseudo-random number generator (PRNG) like the `rand()` function
since they are not secure. In fact, a standard PRNG generates a
sequence of numbers that is too predictable to be used for
cryptographic purposes.

We need a Cryptographically secure pseudorandom number generator
(CSPRNG).  Essentially, a CSPRNG is a PRNG with some additional
properties which guarantee that it is unpredictable. In practice, most
operating systems provide a built-in CSPRNG, and that is what we will
be using for our implementations.

On Unix-like systems, a possible approach is reading bytes from the
`/dev/urandom` file. In this first step, try implementing the
interface declared in the `src/crypt/include/crypt/rand.h` file.

The implementation must be inserted into the `src/crypt/rand.c` file.
The `cr_rand_bytes` function must read `len` bytes from the
`/dev/urandom` file and write them into `buf`. It should return return
0 on success, and -1 on error (ie.  it fails to open the file or it
reads less bytes than `len`.

Once you finished your implementation, the `check_randgen` testsuite
should be passing.

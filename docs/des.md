# An Introduction to DES
We will now look at some block ciphers. Differently from a stream
cipher, a block cipher encrypts a block of plaintext as a whole
producing a a ciphertext block of equal length. A block cipher can
work in different modes, allowing the encryption of messages whose
length is larger than the block size. We will have a look at different
modes of operation in future labs. In this lab, we will introduce the
Data Encryption Standard (DES), which was the most widely used block
cipher before the introduction of AES.

## Freistel Structure
Before going into how DES works, we should introduce the Freistel
Structure.  The Freistel Structure is block cipher design model used
to build various symmetric block ciphers, including DES.

The encruption in a Freistel Structure is iterative. In each round, a
plaintext block is divided into two equal-sized halves: a left half
and a right half. The right half is copied in the left half of the
output block. The right half of the output block is produced by XORing
the left half with the output of a round function applied to the right
half. The round function is a function that takes a round key and a
block returning a block that is the same size as the input.  The final
round simply consists of swapping the left half with the right half.
Similarly, the decryption process is also iterative. In fact, the
decryption process is identical to encruption, but the round keys are
scheduled in reverse order.

## Data Encryption Standard (DES)
The DES is a block cipher based on the Freistel Structure with a
64-bit block size and 16 rounds. However, it has a slight modification
to the classical Freistel Structure that is it performs an initial
permutation to the ciphertext which is inverted before the final
output. Given the DES structure, it remains to define the round
function which takes as input 32 bits of data and 48 bits of key.  The
round function consists of the following 4 steps:

  1. The 32-bit half is expanded to 48 bits. The expansion happens by
  using a table that defines a permutation plus an expansion that
  involves duplication of 16 of the 32 bits.
  2. The 48 bits from the previous step are XORed with the round key.
  3. The resulting 48 bits are divided in 6-bit chunks. Each chunks is
  given to a S-box. An S-box is a non-linear lookup table that takes a
  6-bit input and produces a 4-bit output. The result of this step is
  a 32-bit number.
  4. Finally, the 32-bit block is permuted via a permutation function.


Having defined what happens in each round of DES, we still need to
define how the 48-bit keys for each round are generated. The DES
algorithm takes a 64-bit key as input. Every eighth bit of the key is
ignored resulting into 56 bits. The 56 bits are then permuted and spit
into two halves of 28 bits each. Both halves are left shifted by 1 bit
in rounds 1, 2, 9, and 16, and by 2 buts for all the other
rounds. Finally, the two halves are combined into a 56-bit block which
goes through a permutation.  The final permutation returning 48 bits.

## Triple Data Encryption Algorithm (TDEA)
DES has a some vulnerabilities deriving from a too short key and a
small block size. For this reason, the Triple Data Encryption
Algorithm (TDEA) or 3DES was created. TDEA is based on the idea of
applying DES three times using three DES keys. A 64-bit block in TDEA
is encrypted as follows:

  1. Encrypt the plaintext with the first key.
  2. Decrypt the first ciphertext with the second key.
  3. Encrypt the intermediate ciphertext with the third key.

Notice, that this standard is backward compatible with DES. Meaning
that, if the three keys are the same it is equivalent to encrypting
the plaintext with DES. However, this cipher is quite slow, and other
ciphers such as AES are used in practice.

In this lab, try implementing the `cr_des_*` and `cr_tdea_*` functions
declared in the `src/crypt/include/crypt/des.h` file.  The
implementation must be inserted into the `src/crypt/des.c` file.  Once
you finished your implementation, the `check_des` and `check_tdea`
testsuites should be passing. You can find the details about how the
two cryptosystems work in the relative [NIST
publication](https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf).

# Block Cipher Modes
A block cipher allows to encrypt a single block of a fixed length, but
how do we encrypt data of any length?  Block cipher modes, also known
as modes of operation, are algorithms that describe how to repeatedly
apply a block cipher's single-block operation to securely process data
larger than a single block. The mode of operation defines how the
plaintext is divided into blocks and how these blocks are processed to
produce the ciphertext. Different modes have different security
properties and performance.

To use a block cipher (which encrypts fixed-size blocks of data) on a
message of arbitrary length, the message must be a multiple of the
cipher's block size. Padding is the process of adding extra bytes to
the end of a message to make it the correct length for encryption.
Without padding, the final block of a message that is not a multiple
of the block size would be incomplete, and the encryption algorithm
could not process it correctly. The padding must be designed so that
it can be reliably removed after decryption to recover the original
message. A widely used padding scheme with such characteristics is
PKCS#7. In PKCS#7, the plaintext is padded with a number of bytes
which is equal to the bytes needed to complete a full block. The value
of the padding bytes is the same as the number of the bytes added.
The padding is always added, meaning that when the plaintext length is
a multiple of the block size a full block of padding is added.  Having
an initial introduction to operation modes let's look into some of the
most common operation modes.

  1. Electronic Code Block Mode (ECB).In ECB, each block of the
     plaintext is encrypted independently from each other.
  2. Cipher Block Chaining Mode (CBC). In CBC, each block is first
     XORed with the previous ciphertext block, and then encrypted. For
     the very first block, we do not have a "previous block", so we
     use a random vector named Initialization Vector (IV).
  3. Cipher Feedback Mode (CFB). In CFB, the block cipher is
     effectively turned into a stream cipher. The Initialization
     Vector is encrypted and then XORed with the plaintext to produce
     some ciphertext. The ciphertext becomes the IV for the next
     block.
  4. Output Feedback Mode (OFB). OFB is essentially similar to
     CFB. The only difference is that the encrypted IV becomes the IV
     for the next block, and not the ciphertext block.

In this lab, try implementing the different operation modes by
defining the functions defined by the
`src/crypt/include/crypt/block.h` header file.  The implementation
must be inserted into the `src/crypt/block.c` file.  Once you finished
your implementation, the `check_ecb`, `check_cbc`, `check_cfb` and
`check_ofb` testsuites should be passing.

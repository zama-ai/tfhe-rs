# List of available operations

`concrete-shortint` comes with a set of already implemented functions:


- addition between two ciphertexts
- addition between a ciphertext and an unencrypted scalar
- comparisons `<`, `<=`, `>`, `>=`, `==` between a ciphertext and an unencrypted scalar
- division of a ciphertext by an unencrypted scalar
- LSB multiplication between two ciphertexts returning the result truncated to fit in the `message buffer`
- multiplication of a ciphertext by an unencrypted scalar
- bitwise shift `<<`, `>>`
- subtraction of a ciphertext by another ciphertext
- subtraction of a ciphertext by an unencrypted scalar
- negation of a ciphertext
- bitwise and, or and xor (*)
- comparisons `<`, `<=`, `>`, `>=`, `==` between two ciphertexts (*)
- division between two ciphertexts (*)
- MSB multiplication between two ciphertexts returning the part overflowing the `message buffer` (*)


{% hint style="warning" %}

Currently, certain operations can only be used if the parameter set chosen is compatible with the
bivariate programmable bootstrapping, meaning the carry buffer is larger or equal than the
message buffer. These operations are marked with a star (*).

{% endhint %}



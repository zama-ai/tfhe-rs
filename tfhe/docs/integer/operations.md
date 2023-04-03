# List of available operations

`integer` comes with a set of already implemented functions:


- addition between two ciphertexts
- addition between a ciphertext and an unencrypted scalar
- multiplication of a ciphertext by an unencrypted scalar
- bitwise shift `<<`, `>>`
- bitwise and, or and xor
- multiplication between two ciphertexts
- subtraction of a ciphertext by another ciphertext
- subtraction of a ciphertext by an unencrypted scalar
- negation of a ciphertext

# Types of operations


Much like `shortint`, the operations available via a `ServerKey` may come in different variants:

  - operations that take their inputs as encrypted values.
  - scalar operations take at least one non-encrypted value as input.

For example, the addition has both variants:

  - `ServerKey::unchecked_add` which takes two encrypted values and adds them.
  - `ServerKey::unchecked_scalar_add` which takes an encrypted value and a clear value (the
     so-called scalar) and adds them.

Each operation may come in different 'flavors':

  - `unchecked`: Always does the operation, without checking if the result may exceed the capacity of
     the plaintext space.
  - `checked`: Checks are done before computing the operation, returning an error if operation
      cannot be done safely.
  - `smart`: Always does the operation, if the operation cannot be computed safely, the smart operation
             will propagate the carry buffer to make the operation possible.

Not all operations have these 3 flavors, as some of them are implemented in a way that the operation
is always possible without ever exceeding the plaintext space capacity.

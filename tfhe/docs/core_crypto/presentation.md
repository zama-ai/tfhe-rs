# Quick Start

The `core_crypto` module from `TFHE-rs` is dedicated to the implementation of the cryptographic tools related to TFHE. To construct an FHE application, the [shortint](../fine_grained_api/shortint/tutorial.md) and/or [Boolean](../fine_grained_api/Boolean/tutorial.md) modules (based on `core_crypto`) are recommended.

The `core_crypto` module offers an API to low-level cryptographic primitives and objects, like `lwe_encryption` or `rlwe_ciphertext`. The goal is to propose an easy-to-use API for cryptographers.

The overall code architecture is split in two parts: one for entity definitions and another focused on algorithms. The entities contain the definition of useful types, like LWE ciphertext or bootstrapping keys. The algorithms are then naturally defined to work using these entities.

The API is convenient to add or modify existing algorithms, or to have direct access to the raw data. Even if the LWE ciphertext object is defined, along with functions giving access to the body, it is also possible to bypass these to get directly the $$i^{th}$$ element of LWE mask.

For instance, the code to encrypt and then decrypt a message looks like:

```rust
use tfhe::core_crypto::prelude::*;

// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
// computations
// Define parameters for LweCiphertext creation
let lwe_dimension = LweDimension(742);
let lwe_modular_std_dev = StandardDev(0.000007069849454709433);
let ciphertext_modulus = CiphertextModulus::new_native();

// Create the PRNG
let mut seeder = new_seeder();
let seeder = seeder.as_mut();
let mut encryption_generator =
    EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
let mut secret_generator =
    SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());

// Create the LweSecretKey
let lwe_secret_key =
    allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);

// Create the plaintext
let msg = 3u64;
let plaintext = Plaintext(msg << 60);

// Create a new LweCiphertext
let mut lwe = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size(), ciphertext_modulus);

encrypt_lwe_ciphertext(
    &lwe_secret_key,
    &mut lwe,
    plaintext,
    lwe_modular_std_dev,
    &mut encryption_generator,
);

let decrypted_plaintext = decrypt_lwe_ciphertext(&lwe_secret_key, &lwe);

// Round and remove encoding
// First create a decomposer working on the high 4 bits corresponding to our encoding.
let decomposer = SignedDecomposer::new(DecompositionBaseLog(4), DecompositionLevelCount(1));
let rounded = decomposer.closest_representable(decrypted_plaintext.0);

// Remove the encoding
let cleartext = rounded >> 60;

// Check we recovered the original message
assert_eq!(cleartext, msg);
```

# Overview of the `core_crypto` Module

The `core_crypto` module from TFHE-rs is dedicated to the implementation of the underlying 
cryptographic tools 
related to 
TFHE.
If you want to construct an FHE application, the [shortint](..shortint/tutorial.md) and/or [Boolean]
(../Boolean/tutorial.md) modules (based on this one) are recommended.

The `core_crypto` module offers an API to low-level cryptographic primitives and objects, like 
`lwe_encryption` or `rlwe_ciphertext`. Its goal is to propose an easy-to-use API for 
cryptographers willing to develop a prototype based on usual cryptographic objects. The API is 
also convenient to easily add or modify existing algorithms or to have direct access to the raw 
data. For instance, a definition of an LWE ciphertext is given, along with suitable functions to 
get the mask or the body. However, this is also possible to bypass these utilities to get 
directly the $$i^{th}$$ element of LWE.


The overall architecture is split in two 
parts: one for the entity definitions, and another one focused on the algorithms. 
For instance, the entities contain the definition of useful types, like LWE ciphertext or bootstrapping keys. 
The algorithms are then naturally defined to work using these entities.

For instance, the code to encrypt and then decrypt a message looks like:
```rust
use tfhe::core_crypto::prelude::*;

// DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
// computations
// Define parameters for LweCiphertext creation
let lwe_dimension = LweDimension(742);
let lwe_modular_std_dev = StandardDev(0.000007069849454709433);

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
let mut lwe = LweCiphertext::new(0u64, lwe_dimension.to_lwe_size());

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




```



[comment]: <> (This used to construct higher level abstractions for FHE computations, like the [shortint]&#40;..)
[comment]: <> (/shortint/tutorial.md&#41; and [Boolean]&#40;../Boolean/tutorial.md&#41; modules. It contains tools like ad-hoc CSPRNGs based on [concrete-csprng]&#40;https://crates.io/crates/concrete-csprng&#41; implementations, mathematical objects like polynomials as well as other primitives used in the TFHE cryptosystem like LWE ciphertexts, LWE bootrapping key etc.)





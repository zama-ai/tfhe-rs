# Overview of the `core_crypto` Module

The `core_crypto` module from TFHE-rs contains low-level primitives used to construct higher level abstractions for FHE computations, like the [shortint](../shortint/tutorial.md) and [Boolean](../Boolean/tutorial.md) modules. It contains tools like ad-hoc CSPRNGs based on [concrete-csprng](https://crates.io/crates/concrete-csprng) implementations, mathematical objects like polynomials as well as other primitives used in the TFHE cryptosystem like LWE ciphertexts, LWE bootrapping key etc.

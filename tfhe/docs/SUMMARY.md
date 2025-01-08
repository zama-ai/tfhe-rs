# Table of contents

* [Welcome to TFHE-rs](README.md)

## Get Started

* [What is TFHE-rs?](getting\_started/readme.md)
* [Installation](getting\_started/installation.md)
* [Quick start](getting\_started/quick\_start.md)
* [Types & Operations](getting\_started/operations.md)
* [Benchmarks](getting\_started/benchmarks/summary.md)
  * [CPU Benchmarks](getting\_started/benchmarks/cpu\_benchmarks.md)
  * [GPU Benchmarks](getting\_started/benchmarks/gpu\_benchmarks.md)
  * [Zero-knowledge proof benchmarks](getting_started/benchmarks/zk_proof_benchmarks.md)
* [Security and cryptography](getting\_started/security\_and\_cryptography.md)

## Fundamentals

* [Configuration and key generation](fundamentals/configure-and-generate-keys.md)
* [Server key](fundamentals/set-the-server-key.md)
* [Encryption](fundamentals/encrypt-data.md)
* [Computation on encrypted data](fundamentals/compute.md)
* [Decryption](fundamentals/decrypt-data.md)
* [Encrypted pseudo random values](fundamentals/encrypted-prf.md)
* [Serialization/deserialization](fundamentals/serialization.md)
* [Compressing ciphertexts/keys](fundamentals/compress.md)
* [Debugging](fundamentals/debug.md)

## Guides

* [Rust configuration](guides/rust\_configuration.md)
* [GPU acceleration](guides/run\_on\_gpu.md)
* [Overflow detection](guides/overflow\_operations.md)
* [Data versioning](guides/data\_versioning.md)
* [Public key encryption](guides/public\_key.md)
* [Zero-knowledge proofs](guides/zk-pok.md)
* [Generic trait bounds](guides/trait\_bounds.md)
* [Parallelized PBS](guides/parallelized\_pbs.md)
* [High-level API in C](guides/c\_api.md)
* [JS on WASM API](guides/js\_on\_wasm\_api.md)
* [Multi-threading with Rayon crate](guides/rayon\_crate.md)
* [Trivial ciphertexts](guides/trivial\_ciphertext.md)
* [PBS statistics](guides/pbs-stats.md)
* [Array](guides/array.md)
* [Strings](guides/strings.md)

## Tutorials

* [All tutorials](tutorials/see-all-tutorials.md)
* [Homomorphic parity bit](tutorials/parity\_bit.md)
* [Homomorphic case changing on Ascii string](tutorials/ascii\_fhe\_string.md)
* [SHA256 with Boolean API](tutorials/sha256\_bool.md)

## References

* [API references](https://docs.rs/tfhe/latest/tfhe/)
* [Fine-grained APIs](references/fine-grained-apis/README.md)
  * [Quick start](references/fine-grained-apis/quick\_start.md)
  * [Boolean](references/fine-grained-apis/boolean/README.md)
    * [Operations](references/fine-grained-apis/boolean/operations.md)
    * [Cryptographic parameters](references/fine-grained-apis/boolean/parameters.md)
    * [Serialization/Deserialization](references/fine-grained-apis/boolean/serialization.md)
  * [Shortint](references/fine-grained-apis/shortint/README.md)
    * [Operations](references/fine-grained-apis/shortint/operations.md)
    * [Cryptographic parameters](references/fine-grained-apis/shortint/parameters.md)
    * [Serialization/Deserialization](references/fine-grained-apis/shortint/serialization.md)
  * [Integer](references/fine-grained-apis/integer/README.md)
    * [Operations](references/fine-grained-apis/integer/operations.md)
    * [Cryptographic parameters](references/fine-grained-apis/integer/parameters.md)
    * [Serialization/Deserialization](references/fine-grained-apis/integer/serialization.md)
* [Core crypto API](references/core-crypto-api/README.md)
  * [Quick start](references/core-crypto-api/presentation.md)
  * [Tutorial](references/core-crypto-api/tutorial.md)

## Explanations

* [TFHE deep dive](explanations/tfhe-deep-dive.md)

## Developers

* [Contributing](dev/contributing.md)
* [Release note](https://github.com/zama-ai/tfhe-rs/releases)
* [Feature request](https://github.com/zama-ai/tfhe-rs/issues/new?assignees=\&labels=feature\_request\&projects=\&template=feature\_request.md\&title=)
* [Bug report](https://github.com/zama-ai/tfhe-rs/issues/new?assignees=\&labels=triage\_required\&projects=\&template=bug\_report.md\&title=)

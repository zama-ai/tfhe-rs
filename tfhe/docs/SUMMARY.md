# Table of contents

* [Welcome to TFHE-rs](README.md)

## Getting Started

* [What is TFHE-rs?](getting\_started/readme.md)
* [Installation](getting\_started/installation.md)
* [Quick start](getting\_started/quick\_start.md)
* [Types & Operations](getting\_started/operations.md)
* [Benchmarks](getting\_started/benchmarks.md)
* [Security and cryptography](getting\_started/security\_and\_cryptography.md)

## Fundamentals

* [Configure and generate keys](fundamentals/configure-and-generate-keys.md)
* [Set the server key](fundamentals/set-the-server-key.md)
* [Encrypt data](fundamentals/encrypt-data.md)
* [Compute on encrypted data](fundamentals/compute.md)
* [Decrypt data](fundamentals/decrypt-data.md)
* [Generate encrypted pseudo random values](fundamentals/encrypted-prf.md)
* [Serialize/Deserialize](fundamentals/serialization.md)
* [Compress ciphertexts/Keys](fundamentals/compress.md)
* [Debug](fundamentals/debug.md)

## Guides

* [Configure Rust](guides/rust\_configuration.md)
* [Run on GPU](guides/run\_on\_gpu.md)
* [Detect overflow](guides/overflow\_operations.md)
* [Migrate data to newer versions of TFHE-rs](guides/migrate\_data.md)
* [Use public key encryption](guides/public\_key.md)
* [Generic function bounds](guides/trait\_bounds.md)
* [Use parallelized PBS](guides/parallelized\_pbs.md)
* [Use the C API](guides/c\_api.md)
* [Use the JS on WASM API](guides/js\_on\_wasm\_api.md)
* [Use multi-threading using the rayon crate](guides/rayon\_crate.md)
* [Use trivial ciphertexts](guides/trivial\_ciphertext.md)
* [PBS statistics](guides/pbs-stats.md)

## Tutorials

* [See all tutorials](tutorials/see-all-tutorials.md)
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

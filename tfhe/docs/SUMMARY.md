# Table of contents

* [Welcome to TFHE-rs](README.md)

## Getting Started

* [What is TFHE-rs?](getting-started/what-is-tfhe-rs.md)
* [Installation](getting\_started/installation.md)
* [Quick start](getting\_started/quick\_start.md)
* [Types & Operations](getting\_started/operations.md)
* [Benchmarks](getting\_started/benchmarks.md)
* [Security and cryptography](getting\_started/security\_and\_cryptography.md)

## Tutorials

* [Homomorphic parity bit](tutorials/parity\_bit.md)
* [Homomorphic case changing on Ascii string](tutorials/ascii\_fhe\_string.md)
* [SHA256 with Boolean API](tutorials/sha256\_bool.md)
* [Dark market with integer API](tutorials/dark\_market.md)
* [Homomorphic regular expressions integer API](tutorials/regex.md)
* [See all tutorials](tutorials/see-all-tutorials.md)

## Fundamentals

* [Configure and create keys](fundamentals/configure-and-create-keys.md)
* [Set the server key](fundamentals/set-the-server-key.md)
* [Encrypt data](fundamentals/encrypt-data.md)
* [Compute and decrypt](fundamentals/compute-and-decrypt.md)
* [Serialize/Deserialize](fundamentals/serialization.md)
* [Compress ciphertexts/keys](fundamentals/compress.md)
* [Initialize server-side values](fundamentals/trivial\_ciphertext.md)

## Guides

* [Run on GPU](guides/run\_on\_gpu.md)
* [Configure Rust](guides/rust\_configuration.md)
* [Detect overflow](guides/overflow\_operations.md)
* [Generic function bounds](guides/trait\_bounds.md)
* [Use public key encryption](guides/public\_key.md)
* [Use parallelized PBS](guides/parallelized\_pbs.md)
* [Migrate data to newer versions of TFHE-rs](guides/migrate\_data.md)
* [Use the C API](guides/c\_api.md)
* [Use the JS on WASM API](guides/js\_on\_wasm\_api.md)
* [Use multi-threading using the rayon crate](guides/rayon\_crate.md)
* [Debug](guides/debug.md)
* [Count PBS](guides/count-pbs.md)
* [PRF Generate homomorphic randomness](guides/prf-generate-homomorphic-randomness.md)

## References

* [API references](references/api-references/README.md)
  * [docs.rs](https://docs.rs/tfhe/)
* [Fine-grained APIs](references/fine-grained-apis/README.md)
  * [Quick Start](references/fine-grained-apis/quick\_start.md)
  * [Boolean](references/fine-grained-apis/boolean/README.md)
    * [Operations](references/fine-grained-apis/boolean/operations.md)
    * [Cryptographic Parameters](references/fine-grained-apis/boolean/parameters.md)
    * [Serialization/Deserialization](references/fine-grained-apis/boolean/serialization.md)
  * [Shortint](references/fine-grained-apis/shortint/README.md)
    * [Operations](references/fine-grained-apis/shortint/operations.md)
    * [Cryptographic Parameters](references/fine-grained-apis/shortint/parameters.md)
    * [Serialization/Deserialization](references/fine-grained-apis/shortint/serialization.md)
  * [Integer](references/fine-grained-apis/integer/README.md)
    * [Operations](references/fine-grained-apis/integer/operations.md)
    * [Cryptographic Parameters](references/fine-grained-apis/integer/parameters.md)
    * [Serialization/Deserialization](references/fine-grained-apis/integer/serialization.md)
* [Crypto core API](references/crypto-core-api/README.md)
  * [Quick Start](references/crypto-core-api/presentation.md)
  * [Tutorial](references/crypto-core-api/tutorial.md)

## Developers

* [Contribute](dev/contributing.md)

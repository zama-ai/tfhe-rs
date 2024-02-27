# Table of contents

* [Welcome to TFHE-rs](README.md)

## Getting Started

* [What is TFHE-rs?](getting-started/readme.md)
* [Installation](getting\_started/installation.md)
* [Quick Start](getting\_started/quick\_start.md)
* [Types & Operations](getting\_started/operations.md)
* [Benchmarks](getting\_started/benchmarks.md)
* [Security and Cryptography](getting\_started/security\_and\_cryptography.md)

## Tutorials

* [Homomorphic Parity Bit](tutorials/parity\_bit.md)
* [Homomorphic Case Changing on Ascii String](tutorials/ascii\_fhe\_string.md)
* [SHA256 with Boolean API](tutorials/sha256\_bool.md)
* [Dark Market with Integer API](tutorials/dark\_market.md)
* [Homomorphic Regular Expressions Integer API](tutorials/regex.md)
* [See all tutorials](tutorials/see-all-tutorials.md)

## FUNDAMENTALS

* [Configure and create keys](fundamentals/configure-and-create-keys.md)
* [Set the server key](fundamentals/set-the-server-key.md)
* [Encrypt data](fundamentals/encrypt-data.md)
* [Compute and decrypt](fundamentals/compute-and-decrypt.md)
* [Serialize/Deserialize](foundamentals/serialization.md)
* [Compress ciphertexts/keys](foundamentals/compress.md)
* [Use trivial ciphertext](foundamentals/trivial\_ciphertext.md)

## GUIDES

* [Run on GPU](guides/run\_on\_gpu.md)
* [Configure Rust](guides/rust\_configuration.md)
* [Detect Overflow](guides/overflow\_operations.md)
* [Generic Function Bounds](guides/trait\_bounds.md)
* [Use Public Key Encryption](guides/public\_key.md)
* [Use Parallelized PBS](guides/parallelized\_pbs.md)
* [Migrate Data to Newer Versions of TFHE-rs](guides/migrate\_data.md)
* [Use the C API](guides/c\_api.md)
* [Use the JS on WASM API](guides/js\_on\_wasm\_api.md)
* [Use multi-threading using the rayon crate](guides/rayon\_crate.md)
* [Debug](guides/debug.md)
* [How to count PBS](guides/how-to-count-pbs.md)
* [PRF How to generate homomorphic randomness](guides/prf-how-to-generate-homomorphic-randomness.md)

## REFERENCES

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
* [API References](references/api-references/README.md)
  * [docs.rs](https://docs.rs/tfhe/)
* [Crypto Core API](references/crypto-core-api/README.md)
  * [Quick Start](references/crypto-core-api/presentation.md)
  * [Tutorial](references/crypto-core-api/tutorial.md)

## Developers

* [Contributing](dev/contributing.md)

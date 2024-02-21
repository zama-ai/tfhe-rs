# Table of contents

* [WELCOME](README.md)

## Getting Started

* [What is TFHE-rs?](getting-started/readme.md)
* [Installation](getting\_started/installation.md)
* [Quick Start](getting\_started/quick\_start.md)
* [Types & Operations](getting\_started/operations.md)
* [Benchmarks](getting\_started/benchmarks.md)
* [Security and Cryptography](getting\_started/security\_and\_cryptography.md)

## FUNDAMENTALS

* [Serialize/Deserialize](foundamentals/serialization.md)
* [Compress Ciphertexts/Keys](foundamentals/compress.md)
* [Use Public Key Encryption](foundamentals/public\_key.md)
* [Use Trivial Ciphertext](foundamentals/trivial\_ciphertext.md)

## GUIDES

* [Run on GPU](guides/run\_on\_gpu.md)
* [Configure Rust](guides/rust\_configuration.md)
* [Detect Overflow](guides/overflow\_operations.md)
* [Generic Function Bounds](guides/trait\_bounds.md)
* [Use Parallelized PBS](guides/parallelized\_pbs.md)
* [Migrate Data to Newer Versions of TFHE-rs](guides/migrate\_data.md)
* [Use the C API](guides/c\_api.md)
* [Use the JS on WASM API](guides/js\_on\_wasm\_api.md)
* [Use multi-threading using the rayon crate](guides/rayon\_crate.md)
* [Debug](guides/debug.md)

## Tutorials

* [Homomorphic Parity Bit](tutorials/parity\_bit.md)
* [Homomorphic Case Changing on Ascii String](tutorials/ascii\_fhe\_string.md)
* [SHA256 with Boolean API](tutorials/sha256\_bool.md)
* [Dark Market with Integer API](tutorials/dark\_market.md)
* [Homomorphic Regular Expressions Integer API](tutorials/regex.md)

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

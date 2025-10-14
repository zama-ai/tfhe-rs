# Table of contents

* [Welcome to TFHE-rs](README.md)

## Get Started

* [What is TFHE-rs?](getting-started/README.md)
* [Installation](getting-started/installation.md)
* [Quick start](getting-started/quick-start.md)
* [Benchmarks](getting-started/benchmarks/README.md)
  * [CPU Benchmarks](getting-started/benchmarks/cpu/README.md)
    * [Integer](getting-started/benchmarks/cpu/cpu-integer-operations.md)
    * [Programmable bootstrapping](getting-started/benchmarks/cpu/cpu-programmable-bootstrapping.md)
  * [GPU Benchmarks](getting-started/benchmarks/gpu/README.md)
    * [Integer](getting-started/benchmarks/gpu/gpu-integer-operations.md)
    * [Programmable bootstrapping](getting-started/benchmarks/gpu/gpu-programmable-bootstrapping.md)
  * [HPU Benchmarks](getting-started/benchmarks/hpu/README.md)
    * [Integer](getting-started/benchmarks/hpu/hpu-integer-operations.md)
  * [Zero-knowledge proof benchmarks](getting-started/benchmarks/zk-proof-benchmarks.md)
* [Security and cryptography](getting-started/security-and-cryptography.md)

## FHE Computation

* [Types](fhe-computation/types/README.md)
  * [Integer](fhe-computation/types/integer.md)
  * [Strings](fhe-computation/types/strings.md)
  * [Array](fhe-computation/types/array.md)
  * [KVStore](fhe-computation/types/kv-store.md)
* [Operations](fhe-computation/operations/README.md)
  * [Arithmetic operations](fhe-computation/operations/arithmetic-operations.md)
  * [Bitwise operations](fhe-computation/operations/bitwise-operations.md)
  * [Comparison operations](fhe-computation/operations/comparison-operations.md)
  * [Min/Max operations](fhe-computation/operations/min-max-operations.md)
  * [Ternary conditional operations](fhe-computation/operations/ternary-conditional-operations.md)
  * [Casting operations](fhe-computation/operations/casting-operations.md)
  * [Boolean operations](fhe-computation/operations/boolean-operations.md)
  * [String operations](fhe-computation/operations/string-operations.md)
  * [Dot product](fhe-computation/operations/dot-product.md)
* [Core workflow](fhe-computation/compute/README.md)
  * [Configuration and key generation](fhe-computation/compute/configure-and-generate-keys.md)
  * [Server key](fhe-computation/compute/set-the-server-key.md)
  * [Encryption](fhe-computation/compute/encrypt-data.md)
  * [Decryption](fhe-computation/compute/decrypt-data.md)
  * [Parameters](fhe-computation/compute/parameters.md)
* [Data handling](fhe-computation/data-handling/README.md)
  * [Compressing ciphertexts/keys](fhe-computation/data-handling/compress.md)
  * [Serialization/deserialization](fhe-computation/data-handling/serialization.md)
  * [Data versioning](fhe-computation/data-handling/data-versioning.md)
* [Advanced features](fhe-computation/advanced-features/README.md)
  * [Encrypted pseudo random values](fhe-computation/advanced-features/encrypted-prf.md)
  * [Overflow detection](fhe-computation/advanced-features/overflow-operations.md)
  * [Public key encryption](fhe-computation/advanced-features/public-key.md)
  * [Trivial ciphertexts](fhe-computation/advanced-features/trivial-ciphertext.md)
  * [Zero-knowledge proofs](fhe-computation/advanced-features/zk-pok.md)
  * [Multi-threading with Rayon crate](fhe-computation/advanced-features/rayon-crate.md)
  * [Noise squashing](fhe-computation/advanced-features/noise-squashing.md)
  * [Key upgrade](fhe-computation/advanced-features/upgrade-key-chain.md)
  * [Ciphertexts Rerandomization](fhe-computation/advanced-features/rerand.md)
* [Tooling](fhe-computation/tooling/README.md)
  * [PBS statistics](fhe-computation/tooling/pbs-stats.md)
  * [Generic trait bounds](fhe-computation/tooling/trait-bounds.md)
  * [Debugging](fhe-computation/tooling/debug.md)

## Hardware acceleration
* [GPU acceleration](configuration/gpu-acceleration/run-on-gpu.md)
  * [A simple example](configuration/gpu-acceleration/simple-example.md) 
  * [Operations](configuration/gpu-acceleration/gpu-operations.md)
  * [Compressing ciphertexts](configuration/gpu-acceleration/compressing-ciphertexts.md)
  * [Array types](configuration/gpu-acceleration/array-type.md)
  * [ZK-POKs](configuration/gpu-acceleration/zk-pok.md)
  * [Multi-GPU support](configuration/gpu-acceleration/multi-gpu.md)
* [HPU acceleration](configuration/hpu-acceleration/run-on-hpu.md)
  * [Benchmark](configuration/hpu-acceleration/benchmark.md)

## Configuration

* [Advanced Rust setup](configuration/rust-configuration.md)
* [Parallelized PBS](configuration/parallelized-pbs.md)

## Integration

* [JS on WASM API](integration/js-on-wasm-api.md)
* [High-level API in C](integration/c-api.md)

## Tutorials

* [Homomorphic parity bit](tutorials/parity-bit.md)
* [Homomorphic case changing on Ascii string](tutorials/ascii-fhe-string.md)
* [SHA256 with Boolean API](tutorials/sha256-bool.md)
* [All tutorials](tutorials/see-all-tutorials.md)

## References

* [API references](https://docs.rs/tfhe/latest/tfhe/)
* [Fine-grained APIs](references/fine-grained-apis/README.md)
  * [Quick start](references/fine-grained-apis/quick-start.md)
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

* [Contributing](../../CONTRIBUTING.md)
* [Release note](https://github.com/zama-ai/tfhe-rs/releases)
* [Feature request](https://github.com/zama-ai/tfhe-rs/issues/new?assignees=\&labels=feature_request\&projects=\&template=feature_request.md\&title=)
* [Bug report](https://github.com/zama-ai/tfhe-rs/issues/new?assignees=\&labels=triage_required\&projects=\&template=bug_report.md\&title=)

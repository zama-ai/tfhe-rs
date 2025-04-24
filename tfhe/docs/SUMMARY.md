# Table of contents

* [Welcome to TFHE-rs](README.md)

## Get Started

* [What is TFHE-rs?](getting_started/README.md)
* [Installation](getting_started/installation.md)
* [Quick start](getting_started/quick_start.md)
* [Benchmarks](getting_started/benchmarks/README.md)
  * [CPU Benchmarks](getting_started/benchmarks/cpu/README.md)
    * [Integer](getting_started/benchmarks/cpu/cpu_integer_operations.md)
    * [Programmable bootstrapping](getting_started/benchmarks/cpu/cpu_programmable_bootstrapping.md)
  * [GPU Benchmarks](getting_started/benchmarks/gpu/README.md)
    * [Integer](getting_started/benchmarks/gpu/gpu_integer_operations.md)
    * [Programmable bootstrapping](getting_started/benchmarks/gpu/gpu_programmable_bootstrapping.md)
  * [HPU Benchmarks](getting_started/benchmarks/hpu/README.md)
    * [Integer](getting_started/benchmarks/hpu/hpu_integer_operations.md)
  * [Zero-knowledge proof benchmarks](getting_started/benchmarks/zk_proof_benchmarks.md)
* [Security and cryptography](getting_started/security_and_cryptography.md)

## FHE Computation

* [Types](fhe-computation/types/README.md)
  * [Integer](fhe-computation/types/integer.md)
  * [Strings](fhe-computation/types/strings.md)
  * [Array](fhe-computation/types/array.md)
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
  * [Data versioning](fhe-computation/data-handling/data_versioning.md)
* [Advanced features](fhe-computation/advanced-features/README.md)
  * [Encrypted pseudo random values](fhe-computation/advanced-features/encrypted-prf.md)
  * [Overflow detection](fhe-computation/advanced-features/overflow_operations.md)
  * [Public key encryption](fhe-computation/advanced-features/public_key.md)
  * [Trivial ciphertexts](fhe-computation/advanced-features/trivial_ciphertext.md)
  * [Zero-knowledge proofs](fhe-computation/advanced-features/zk-pok.md)
  * [Multi-threading with Rayon crate](fhe-computation/advanced-features/rayon_crate.md)
* [Tooling](fhe-computation/tooling/README.md)
  * [PBS statistics](fhe-computation/tooling/pbs-stats.md)
  * [Generic trait bounds](fhe-computation/tooling/trait_bounds.md)
  * [Debugging](fhe-computation/tooling/debug.md)

## Configuration

* [Advanced Rust setup](configuration/rust_configuration.md)
* [GPU acceleration](configuration/gpu_acceleration/run_on_gpu.md)
  * [Operations](configuration/gpu_acceleration/gpu_operations.md)
  * [Benchmark](configuration/gpu_acceleration/benchmark.md)
  * [Compressing ciphertexts](configuration/gpu_acceleration/compressing_ciphertexts.md)
  * [Array types](configuration/gpu_acceleration/array_type.md)
  * [Multi-GPU support](configuration/gpu_acceleration/multi_gpu.md)
* [HPU acceleration](configuration/hpu_acceleration/run_on_hpu.md)
  * [Benchmark](configuration/hpu_acceleration/benchmark.md)
* [Parallelized PBS](configuration/parallelized_pbs.md)

## Integration

* [JS on WASM API](integration/js_on_wasm_api.md)
* [High-level API in C](integration/c_api.md)

## Tutorials

* [Homomorphic parity bit](tutorials/parity_bit.md)
* [Homomorphic case changing on Ascii string](tutorials/ascii_fhe_string.md)
* [SHA256 with Boolean API](tutorials/sha256_bool.md)
* [All tutorials](tutorials/see-all-tutorials.md)

## References

* [API references](https://docs.rs/tfhe/latest/tfhe/)
* [Fine-grained APIs](references/fine-grained-apis/README.md)
  * [Quick start](references/fine-grained-apis/quick_start.md)
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

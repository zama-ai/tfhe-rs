# GPU acceleration

**TFHE-rs** has a CUDA GPU backend  that enables faster integer arithmetic operations on encrypted data, when compared to the default CPU backend. This guide explains how to update your existing program to leverage GPU acceleration, or to start a new program using GPU. 

To explore a simple code example, go to:
{% content-ref url="./simple-example.md" %} A simple TFHE-rs GPU example {% endcontent-ref %}

## FHE performance on GPU

The GPU backend is **up to 4.2x faster** than the CPU one. For a comparison between CPU and GPU latencies, see the following page.
{% content-ref url="../../getting-started/benchmarks/README.md" %} GPU vs CPU benchmarks {% endcontent-ref %}

Different integer operations obtain different speedups. Please refer to the [detailed GPU benchmarks of FHE operations](../../getting-started/benchmarks/gpu/README.md) for detailed figures.

{% hint style="warning" %}
To reproduce TFHE-rs GPU benchmarks, see [this dedicated page](../../getting-started/benchmarks/gpu/gpu-programmable-bootstrapping.md). To obtain the best performance when running benchmarks, set the environment variable `CUDA_MODULE_LOADING=EAGER` to avoid CUDA API overheads during the first kernel execution. Bear in mind that GPU warmup is necessary before doing performance measurements.
{% endhint %}

## GPU TFHE-rs features

By default, the GPU backend uses specific cryptographic parameters. When calling the [`tfhe::ConfigBuilder::default()`](https://doc.rust-lang.org/nightly/core/default/trait.Default.html#tymethod.default) function, the cryptographic for PBS will be:
- PBS parameters: [`PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS`](https://docs.rs/tfhe/latest/tfhe/shortint/parameters/aliases/constant.PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS.html)

These PBS parameters are accompanied by the following compression parameters: 
- Compression parameters: [`COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS`](https://docs.rs/tfhe/latest/tfhe/shortint/parameters/aliases/constant.COMP_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS.html)

TFHE-rs uses dedicated parameters for the GPU in order to achieve optimal performance, and the CPU and GPU parameters cannot be mixed to perform computation and compression for security reasons.

The GPU backend is designed to speed up server-side FHE operations and supports the following TFHE-rs features:

- [FHE ciphertext operations](./gpu-operations.md)
- [Ciphertext compression](./compressing-ciphertexts.md)
- [Ciphertext arrays](array-type.md)
- [ZK-POK proof expansion](zk-pok.md)
- [Noise Squashing](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.squash_noise)
- [Multi-GPU for throughput optimization](./multi-gpu.md) 

The following features are not supported:

- Key generation
- Encryption/decryption
- ZK-POK proof generation and verification
- Encrypted strings and operations on encrypted strings

## GPU programming model

The GPU TFHE-rs integer API is mostly identical to the CPU API: both integer datatypes and operations syntax are the same. All the while, some GPU program design principles must be considered:
* Key generation, encryption, and decryption are performed on the CPU. When used in operations, ciphertexts are automatically copied to or from the first GPU that the user configures for TFHE-rs.
* GPU syntax for integer FHE operations, key generation, and serialization is identical with equivalent CPU code.
* When configured to compile for the GPU, TFHE-rs uses GPU specific cryptographic parameters that give high performance on the GPU. Ciphertexts and server-keys that are generated with CPU parameters can be processed with GPU-enabled TFHE-rs but performance is considerably degraded.
* Each server key instance is assigned to a set of GPUs, which are automatically used in parallel. To set the active GPUs for a CPU thread, activate the server key assigned to the GPUs you want to use.
* GPU integer operations are synchronous to the calling thread. To execute in parallel on several GPUs, use Rust parallel constructs such as `par_iter`.

The key differences between the CPU API and the GPU API are:
* The GPU backend only supports compressed server keys that must be decompressed on a GPU selected by the user.
* For ciphertext compression the cryptographic parameters must be chosen by the user from the GPU parameter set.
* For ciphertext arrays, GPU-specific ciphertext array types must be used instead of CPU ones.

## Project configuration

### 1. Prerequisites

To compile and execute GPU TFHE-rs programs, make sure your system has the following software installed.

* Cuda version >= 10
* Compute Capability >= 3.0
* [gcc](https://gcc.gnu.org/) >= 8.0 - check this [page](https://gist.github.com/ax3l/9489132) for more details about nvcc/gcc compatible versions
* [cmake](https://cmake.org/) >= 3.24
* libclang, to match Rust bingen [requirements](https://rust-lang.github.io/rust-bindgen/requirements.html) >= 9.0
* Rust version - see this [page](../rust-configuration.md)

### 2. Import GPU-enabled TFHE-rs

To use the **TFHE-rs** GPU backend in your project, add the following dependency in your `Cargo.toml`.

```toml
tfhe = { version = "~1.5.3", features = ["boolean", "shortint", "integer", "gpu"] }
```

If none of the supported backends is configured in `Cargo.toml`, the CPU backend is used.

{% hint style="success" %}
For optimal performance when using **TFHE-rs**, run your code in release mode with the `--release` flag.
{% endhint %}

### 3. Supported platforms

The **TFHE-rs** GPU backend is supported on Linux (x86, aarch64). The following table lists compatibility status for other platforms.

| OS      | x86 | aarch64 |
| ------- |-----|---------|
| Linux   | Yes | Yes     |
| macOS   | No  | No      |
| Windows | No  | No      |

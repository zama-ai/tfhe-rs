# GPU acceleration

**TFHE-rs** has a CUDA GPU backend  that enables faster integer arithmetic operations on encrypted data, when compared to the default CPU backend. This guide explains how to update your existing program to leverage GPU acceleration, or to start a new program using GPU. 

1. [GPU FHE Performance Summary](#performance)
2. [GPU TFHE-rs features](#gpu-tfhe-rs-features)
3. [GPU Programming Model](#gpu-programming-model)
4. [Project Configuration](#gpu-programming-quick-start)

For a simple code example, go to:
{% content-ref url="./simple_example.md" %} A simple TFHE-rs GPU example {% endcontent-ref %}

## FHE Performance on GPU

The GPU backend is, on average, **between 1.6x and 4.2x faster** than the CPU one, depending on the type of integer operation. For a comparison, see the following page.    
{% content-ref url="../../getting_started/benchmarks/README.md" %} GPU vs CPU benchmarks {% endcontent-ref %}

Please refer to the [detailed GPU benchmarks of FHE operations](../../getting_started/benchmarks/gpu/README.md) for detailed performance figures.

{% hint style="warning" %}
When measuring GPU times on your own on Linux, set the environment variable `CUDA_MODULE_LOADING=EAGER` to avoid CUDA API overheads during the first kernel execution.
{% endhint %}

## GPU TFHE-rs features

The GPU backend is designed to speed up server-side FHE operations and supports the following TFHE-rs features:

- [FHE ciphertext operations](./gpu_operations.md)
- [Ciphertext compression](./compressing_ciphertexts.md)
- [Ciphertext arrays](array_type.md)
- [ZK-POK expansion](./zk-pok.md)
- [Multi-GPU for throughput optimization](./multi_gpu.md) 

The following features are not supported:

- Encryption/decryption
- ZK-POK generation and verification

## GPU Programming model

The GPU TFHE-rs integer API is mostly identical to the CPU API: both integer datatypes and operations syntax are the same. All the while, some GPU program design principles must be considered:
1. Key generation, encryption, and decryption are performed on the CPU. When used in operations, ciphertexts are automatically copied to or from the first GPU that the user configures for TFHE-rs.
2. GPU syntax for integer FHE operations, key generation, and serialization is identical with equivalent CPU code.
3. When configured to compile for the GPU, TFHE-rs uses specific crypto-system parameters. Ciphertexts that are encrypted with CPU parameters cannot be processed with GPU server keys. Server keys generated with the CPU backend are not compatible with the GPU backend.  
4. Each server key instance is assigned to a single GPU while the backend can use multiple GPUs in parallel. To set the current GPU assigned to a CPU thread, activate the server key assigned to the GPU you want to use.
5. GPU integer operations are synchronous to the calling thread. To execute in parallel on several GPUs, use Rust parallel constructs such as `par_iter`.  

The key differences between the CPU API and the GPU API are:
1. The GPU backend only supports compressed server keys that must be decompressed on a GPU selected by the user.
2. For ciphertext compression the crypto-system parameters must be chosen by the user from the GPU parameter set.
3. For ciphertext arrays, GPU-specific ciphertext array types must be used instead of CPU ones. 

## Project configuration

### 1. Prerequisites

To compile and execute GPU TFHE-rs programs, make sure your system has the following software installed.

* Cuda version >= 10
* Compute Capability >= 3.0
* [gcc](https://gcc.gnu.org/) >= 8.0 - check this [page](https://gist.github.com/ax3l/9489132) for more details about nvcc/gcc compatible versions
* [cmake](https://cmake.org/) >= 3.24
* libclang, to match Rust bingen [requirements](https://rust-lang.github.io/rust-bindgen/requirements.html) >= 9.0
* Rust version - see this [page](../rust_configuration.md)

### 2. Import GPU-enabled TFHE-rs

To use the **TFHE-rs** GPU backend in your project, add the following dependency in your `Cargo.toml`.

```toml
tfhe = { version = "~1.2.0", features = ["boolean", "shortint", "integer", "gpu"] }
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


# GPU acceleration

**TFHE-rs** has a CUDA GPU backend  that enables faster integer arithmetic operations on encrypted data, when compared to the default CPU backend. This guide explains how to update your existing program to leverage GPU acceleration, or to start a new program using GPU. 

1. [FHE Performance on GPU](#performance)
2. [GPU programming model](#gpu-programming-model)
3. [Quick start](#gpu-programming-quick-start)

## FHE Performance on GPU

The GPU backend is, on average, **between 1.6x and 4.2x faster** than the CPU one, depending on the type of integer operation. For a detailed comparison, see the following page.    
{% content-ref url="../../getting_started/benchmarks/README.md" %} GPU vs CPU benchmarks {% endcontent-ref %}

## GPU Programming model

The GPU TFHE-rs integer API is identical to the CPU API in all respects but one: server keys must be copied to one or multiple GPUs. While the API is otherwise identical to the CPU, some GPU program design principles must be considered:
1. Key Generation, Encryption and Decryption are performed on the CPU. When used in operations, ciphertexts are automatically stored on the first available GPU.
2. GPU code that performs integer FHE operations is identical with equivalent CPU code.
3. The GPU backend has specific crypto-system parameters. Ciphertexts that are encrypted with CPU parameters cannot be processed with GPU server keys. Server keys generated with the CPU backend are not compatible with the GPU backend.  
4. Each server key instance is assigned to a single GPU. The GPU backend can use multiple GPUs. To set the current GPU, activate the server key assigned to the GPU you want to use.
5. GPU integer operations are synchronous to the calling thread. To execute in parallel on several GPUs, use Rust parallel constructs such as `par_iter`.  

## GPU programming quick start

### 1. Prerequisites

To compile and execute GPU TFHE-rs programs, make sure your system has the following software installed.

* Cuda version >= 10
* Compute Capability >= 3.0
* [gcc](https://gcc.gnu.org/) >= 8.0 - check this [page](https://gist.github.com/ax3l/9489132) for more details about nvcc/gcc compatible versions
* [cmake](https://cmake.org/) >= 3.24
* libclang, to match Rust bingen [requirements](https://rust-lang.github.io/rust-bindgen/requirements.html) >= 9.0
* Rust version - check this [page](../rust_configuration.md)

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

**TFHE-rs** GPU backend is supported on Linux (x86, aarch64).

| OS      | x86         | aarch64       |
| ------- | ----------- |---------------|
| Linux   | Supported   | Supported     |
| macOS   | Unsupported | Unsupported   |
| Windows | Unsupported | Unsupported   |


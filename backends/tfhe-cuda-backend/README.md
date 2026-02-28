# TFHE Cuda backend

## Introduction

The `tfhe-cuda-backend` holds the code for GPU acceleration of Zama's variant of TFHE.
It implements CUDA/C++ functions to perform homomorphic operations on LWE ciphertexts.

It provides functions to allocate memory on the GPU, to copy data back 
and forth between the CPU and the GPU, to create and destroy Cuda streams, etc.:
- `cuda_create_stream`, `cuda_destroy_stream`
- `cuda_malloc`, `cuda_check_valid_malloc`
- `cuda_memcpy_async_to_cpu`, `cuda_memcpy_async_to_gpu`
- `cuda_get_number_of_gpus`
- `cuda_synchronize_device`
The cryptographic operations it provides are:
- an implementation of the classical TFHE programmable bootstrap,
- an implementation of the multi-bit TFHE programmable bootstrap,
- the keyswitch,
- acceleration for leveled operations,
- acceleration for arithmetics over encrypted integers of arbitrary size, 
- acceleration for integer compression/decompression.

## Dependencies

**Disclaimer**: Compilation on Windows/Mac is not supported yet. Only Nvidia GPUs are supported. 

- nvidia driver - for example, if you're running Ubuntu 20.04 check this [page](https://linuxconfig.org/how-to-install-the-nvidia-drivers-on-ubuntu-20-04-focal-fossa-linux) for installation. You need an Nvidia GPU with Compute Capability >= 3.0
- [nvcc](https://docs.nvidia.com/cuda/cuda-installation-guide-linux/index.html) >= 10.0
- [gcc](https://gcc.gnu.org/) >= 8.0 - check this [page](https://gist.github.com/ax3l/9489132) for more details about nvcc/gcc compatible versions
- [cmake](https://cmake.org/) >= 3.24
- libclang, to match Rust bingen [requirements](https://rust-lang.github.io/rust-bindgen/requirements.html) >= 9.0

## Build

The Cuda project held in `tfhe-cuda-backend` can be compiled independently of TFHE-rs in the following way:
```
git clone git@github.com:zama-ai/tfhe-rs
cd backends/tfhe-cuda-backend/cuda
mkdir build
cd build
cmake ..
make
```
The compute capability is detected automatically (with the first GPU information) and set accordingly.
If your machine does not have an available Nvidia GPU, the compilation will work if you have the nvcc compiler installed. The generated executable will target a 7.0 compute capability (sm_70).

## Links

- [TFHE](https://eprint.iacr.org/2018/421.pdf)

## License

This software is distributed under the BSD-3-Clause-Clear license. If you have any questions,
please contact us at `hello@zama.org`.

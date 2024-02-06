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
- an amortized implementation of the TFHE programmable bootstrap: `cuda_bootstrap_amortized_lwe_ciphertext_vector_32` and `cuda_bootstrap_amortized_lwe_ciphertext_vector_64`
- a low latency implementation of the TFHE programmable bootstrap: `cuda_bootstrap_low latency_lwe_ciphertext_vector_32` and `cuda_bootstrap_low_latency_lwe_ciphertext_vector_64`
- the keyswitch: `cuda_keyswitch_lwe_ciphertext_vector_32` and `cuda_keyswitch_lwe_ciphertext_vector_64`
- the larger precision programmable bootstrap (wop PBS, which supports up to 16 bits of message while the classical PBS only supports up to 8 bits of message) and its sub-components: `cuda_wop_pbs_64`, `cuda_extract_bits_64`, `cuda_circuit_bootstrap_64`, `cuda_cmux_tree_64`, `cuda_blind_rotation_sample_extraction_64`
- acceleration for leveled operations: `cuda_negate_lwe_ciphertext_vector_64`, `cuda_add_lwe_ciphertext_vector_64`, `cuda_add_lwe_ciphertext_vector_plaintext_vector_64`, `cuda_mult_lwe_ciphertext_vector_cleartext_vector`.

## Dependencies

**Disclaimer**: Compilation on Windows/Mac is not supported yet. Only Nvidia GPUs are supported. 

- nvidia driver - for example, if you're running Ubuntu 20.04 check this [page](https://linuxconfig.org/how-to-install-the-nvidia-drivers-on-ubuntu-20-04-focal-fossa-linux) for installation
- [nvcc](https://docs.nvidia.com/cuda/cuda-installation-guide-linux/index.html) >= 10.0
- [gcc](https://gcc.gnu.org/) >= 8.0 - check this [page](https://gist.github.com/ax3l/9489132) for more details about nvcc/gcc compatible versions
- [cmake](https://cmake.org/) >= 3.24

## Build

The Cuda project held in `tfhe-cuda-backend` can be compiled independently from TFHE-rs in the following way:
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
please contact us at `hello@zama.ai`.

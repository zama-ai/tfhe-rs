# Benchmarks

This document summarizes the timings of some homomorphic operations over 64-bit encrypted integers, depending on the hardware. More details are given for [the CPU](cpu/README.md), [the GPU](gpu/README.md), or [zeros-knowledge proofs](zk_proof_benchmarks.md).

The cryptographic parameters used for benchmarking follow a tweaked uniform (TUniform) noise distribution instead of a Gaussian. The main advantage of this distribution is to be bounded, whereas the usual Gaussian one is not. In some practical cases, this can simplify the use of homomorphic computation. See the [noise section](../security_and_cryptography.md#noise) of the Security and cryptography documentation page for more information on the noise distributions.

You can get the parameters used for benchmarks by cloning the repository and checking out the commit you want to use (starting with the v0.8.0 release) and run the following make command:

```console
make print_doc_bench_parameters
```

### Operation time over FheUint 64

![](../../_static/cpu_gpu_integer_benchmark_fheuint64_tuniform_2m64_ciphertext.svg)

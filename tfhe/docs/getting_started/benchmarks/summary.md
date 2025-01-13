# Benchmarks

This document summarizes the timings of some homomorphic operations over 64-bit encrypted integers, depending on the hardware. More details are given for [the CPU](cpu\_benchmarks.md), [the GPU](gpu\_benchmarks.md), or [zeros-knowledge proofs](zk\_proof\_benchmarks.md).

The cryptographic parameters used for benchmarking follow a tweaked uniform (TUniform) noise distribution instead of a Gaussian. The main advantage of this distribution is to be bounded, whereas the usual Gaussian one is not. In some practical cases, this can simplify the use of homomorphic computation. See the [noise section](../security\_and\_cryptography.md#noise) of the Security and cryptography documentation page for more information on the noise distributions.

You can get the parameters used for benchmarks by cloning the repository and checking out the commit you want to use (starting with the v0.11.0 release) and run the following make command:

```console
make print_doc_bench_parameters
```

### Operation time (ms) over FheUint 64

{% embed url="https://docs.google.com/spreadsheets/d/1OMdGSakEUbIFSEQKhAinTolJjvmPBbafi3DEe3UfzsQ/edit?usp=sharing" %}

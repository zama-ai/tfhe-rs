# Integer Operations over HPU

This document details the HPU performance benchmarks of homomorphic operations on integers using **TFHE-rs**.

{% hint style="info" %}
All HPU benchmarks were launched on AMD Alveo v80 FPGAs.
{% endhint %}

The cryptographic parameters `HPU_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128` were used.

## 1xHPU
Below are the results for the execution on a single Alveo v80 board.
The following table shows the performance when the inputs of the benchmarked operation are encrypted:

![](../../../_static/hpu_integer_benchmark_hpux1_tuniform_2m128_ciphertext.svg)

The following table shows the performance when the left input of the benchmarked operation is encrypted and the other is a clear scalar of the same size:

![](../../../_static/hpu_integer_benchmark_hpux1_tuniform_2m128_plaintext.svg)

## Reproducing TFHE-rs benchmarks

**TFHE-rs** benchmarks can be easily reproduced from the [source](https://github.com/zama-ai/tfhe-rs).

The following example shows how to reproduce **TFHE-rs** benchmarks:

```shell
#Integer benchmarks:
make bench_integer_hpu
```

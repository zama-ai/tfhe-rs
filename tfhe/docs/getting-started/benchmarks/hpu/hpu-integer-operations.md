# Integer Operations over HPU

This document details the HPU performance benchmarks of homomorphic operations on integers using **TFHE-rs**.

{% hint style="info" %}
All HPU benchmarks were launched on AMD Alveo v80 FPGAs.
{% endhint %}

The cryptographic parameters `HPU_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128` were used.

## 1xHPU
Below are the results for the execution on a single Alveo v80 board.

The following tables show the performance when the inputs of the benchmarked operation are encrypted:

### Latency

![](../../../.gitbook/assets/hpu-integer-benchmark-hpux1-tuniform-2m128-ciphertext.svg)

### Throughput

![](../../../.gitbook/assets/hpu-integer-benchmark-hpux1-tuniform-2m128-ciphertext-throughput.svg)

The following tables show the performance when the left input of the benchmarked operation is encrypted and the other is a clear scalar of the same size:

### Latency

![](../../../.gitbook/assets/hpu-integer-benchmark-hpux1-tuniform-2m128-plaintext.svg)

### Throughput

![](../../../.gitbook/assets/hpu-integer-benchmark-hpux1-tuniform-2m128-plaintext-throughput.svg)

## Reproducing TFHE-rs benchmarks

**TFHE-rs** benchmarks can be easily reproduced from the [source](https://github.com/zama-ai/tfhe-rs).

The following example shows how to reproduce **TFHE-rs** benchmarks:

```shell
#Integer benchmarks:
make bench_integer_hpu
```

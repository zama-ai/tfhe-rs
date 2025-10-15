# Integer Operations over GPU

This document details the GPU performance benchmarks of homomorphic operations on integers using **TFHE-rs**.

{% hint style="info" %}
All GPU benchmarks were launched on H100 GPUs, and rely on the multithreaded PBS algorithm.
{% endhint %}

The cryptographic parameters `PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS` were used.

## Pfail: $$2^{-128}$$
### 8xH100-SXM5
Below come the results for the execution on eight H100 using SXM technology.
The following tables show the performance when the inputs of the benchmarked operation are encrypted:

### Latency

![](../../../.gitbook/assets/gpu-integer-benchmark-h100x8-sxm5-multi-bit-tuniform-2m128-ciphertext.svg)

### Throughput

![](../../../.gitbook/assets/gpu-integer-benchmark-h100x8-sxm5-multi-bit-tuniform-2m128-ciphertext-throughput.svg)

The following tables show the performance when the left input of the benchmarked operation is encrypted and the other is a clear scalar of the same size:

### Latency

![](../../../.gitbook/assets/gpu-integer-benchmark-h100x8-sxm5-multi-bit-tuniform-2m128-plaintext.svg)

### Throughput

![](../../../.gitbook/assets/gpu-integer-benchmark-h100x8-sxm5-multi-bit-tuniform-2m128-plaintext-throughput.svg)

## Reproducing TFHE-rs benchmarks

**TFHE-rs** benchmarks can be easily reproduced from the [source](https://github.com/zama-ai/tfhe-rs).

The following example shows how to reproduce **TFHE-rs** benchmarks:

```shell
#Integer benchmarks:
make bench_integer_gpu
```

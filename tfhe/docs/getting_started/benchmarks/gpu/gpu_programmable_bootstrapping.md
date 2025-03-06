# Programmable bootstrapping over GPU

This document details the GPU performance benchmarks of programmable bootstrapping and keyswitch operations using **TFHE-rs**.

{% hint style="info" %}
All GPU benchmarks were launched on H100 GPUs, and rely on the multithreaded PBS algorithm with a grouping factor set to 3.
{% endhint %}

## P-fail: $$2^{-40}$$

![](../../../_static/gpu_pbs_benchmark_tuniform_2m40.svg)

## P-fail: $$2^{-64}$$

![](../../../_static/gpu_pbs_benchmark_tuniform_2m64.svg)

## Reproducing TFHE-rs benchmarks

**TFHE-rs** benchmarks can be easily reproduced from the [source](https://github.com/zama-ai/tfhe-rs).

The following example shows how to reproduce **TFHE-rs** benchmarks:

```shell
#PBS benchmarks:
make bench_pbs_gpu

#KS-PBS benchmarks:
make bench_ks_pbs_gpu
```

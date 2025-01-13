# CPU Benchmarks

This document details the CPU performance benchmarks of homomorphic operations using **TFHE-rs**.

By their nature, homomorphic operations run slower than their cleartext equivalents. The following are the timings for basic operations, including benchmarks from other libraries for comparison.

{% hint style="info" %}
All CPU benchmarks were launched on an `AWS hpc7a.96xlarge` instance equipped with an `AMD EPYC 9R14 CPU @ 2.60GHz` and 740GB of RAM.
{% endhint %}

## Integer operations

The following tables benchmark the execution time of some operation sets using `FheUint` (unsigned integers). The `FheInt` (signed integers) performs similarly.

The next table shows the operation timings on CPU when all inputs are encrypted

{% embed url="https://docs.google.com/spreadsheets/d/1b_-72ArnSdaqfr-gJOnMmVdcBokYZohnylO4LUj2PMw/edit?usp=sharing" %}

The next table shows the operation timings on CPU when the left input is encrypted and the right is a clear scalar of the same size:

{% embed url="https://docs.google.com/spreadsheets/d/1m3tjCi_2GSIHop2zZLAtVbhdDn5wqTGd2lOA3CcJe-U/edit?usp=sharing" %}

All timings are based on parallelized Radix-based integer operations where each block is encrypted using the default parameters `PARAM_MESSAGE_2_CARRY_2_KS_PBS`. To ensure predictable timings, we perform operations in the `default` mode, which ensures that the input and output encoding are similar (i.e., the carries are always emptied).

You can minimize operational costs by selecting from 'unchecked', 'checked', or 'smart' modes from [the fine-grained APIs](../../references/fine-grained-apis/quick\_start.md), each balancing performance and correctness differently. For more details about parameters, see [here](../../references/fine-grained-apis/shortint/parameters.md). You can find the benchmark results on GPU for all these operations [here](../../guides/run\_on\_gpu.md#benchmarks).

## Programmable bootstrapping

The next table shows the execution time of a keyswitch followed by a programmable bootstrapping depending on the precision of the input message. The associated parameter set is given. The configuration is Concrete FFT + AVX-512.

Note that these benchmarks use Gaussian parameters.

{% embed url="https://docs.google.com/spreadsheets/d/1o6MWpbzbYhDs3Pnoq-2hlNEgO9G8wGR5niW-OOZ6c_4/edit?usp=sharing" %}

## Reproducing TFHE-rs benchmarks

**TFHE-rs** benchmarks can be easily reproduced from the [source](https://github.com/zama-ai/tfhe-rs).

{% hint style="info" %}
AVX512 is now enabled by default for benchmarks when available
{% endhint %}

The following example shows how to reproduce **TFHE-rs** benchmarks:

```shell
#Boolean benchmarks:
make bench_boolean

#Integer benchmarks:
make bench_integer

#Shortint benchmarks:
make bench_shortint
```

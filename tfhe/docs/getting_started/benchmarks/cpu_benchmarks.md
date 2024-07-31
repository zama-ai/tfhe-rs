# CPU Benchmarks

This document details the CPU performance benchmarks of homomorphic operations using **TFHE-rs**.

By their nature, homomorphic operations run slower than their cleartext equivalents. The following are the timings for basic operations, including benchmarks from other libraries for comparison.

{% hint style="info" %}
All CPU benchmarks were launched on an `AWS hpc7a.96xlarge` instance equipped with an `AMD EPYC 9R14 CPU @ 2.60GHz` and 740GB of RAM.
{% endhint %}

## Integer operations

The following tables benchmark the execution time of some operation sets using `FheUint` (unsigned integers). The `FheInt` (signed integers) performs similarly.

The next table shows the operation timings on CPU when all inputs are encrypted:

| Operation \ Size                                       |  `FheUint8` | `FheUint16` | `FheUint32` | `FheUint64` | `FheUint128` | `FheUint256` |
| ------------------------------------------------------ |  ---------- | ----------- | ----------- | ----------- | ------------ | ------------ |
| Negation (`-`)                                         |  65.1 ms    | 97.0 ms     | 116 ms      | 141 ms      | 186 ms       | 227 ms       |
| Add / Sub (`+`,`-`)                                    |  75.8 ms    | 96.7 ms     | 118 ms      | 150 ms      | 186 ms       | 230 ms       |
| Mul (`x`)                                              |  96.1 ms    | 180 ms      | 251 ms      | 425 ms      | 1.1 s        | 3.66 s       |
| Equal / Not Equal (`eq`, `ne`)                         |  32.2 ms    | 35.0 ms     | 55.4 ms     | 56.0 ms     | 59.5 ms      | 60.7 ms      |
| Comparisons  (`ge`, `gt`, `le`, `lt`)                  |  57.1 ms    | 72.9 ms     | 93.0 ms     | 116 ms      | 138 ms       | 164 ms       |
| Max / Min   (`max`,`min`)                              |  94.3 ms    | 114 ms      | 138 ms      | 159 ms      | 189 ms       | 233 ms       |
| Bitwise operations (`&`, `\|`, `^`)                    |  19.6 ms    | 20.1 ms     | 20.2 ms     | 21.7 ms     | 23.9 ms      | 25.7 ms      |
| Div / Rem  (`/`, `%`)                                  |  711 ms     | 1.81 s      | 4.43 s      | 10.5 s      | 25.1 s       | 63.2 s       |
| Left / Right Shifts (`<<`, `>>`)                       |  99.5 ms    | 125 ms      | 155 ms      | 190 ms      | 234 ms       | 434 ms       |
| Left / Right Rotations (`left_rotate`, `right_rotate`) |  101 ms     | 125 ms      | 154 ms      | 188 ms      | 234 ms       | 430 ms       |
| Leading / Trailing zeros/ones                          |  96.7 ms    | 155 ms      | 181 ms      | 241 ms      | 307 ms       | 367 ms       |
| Log2                                                   |  112 ms     | 176 ms      | 200 ms      | 265 ms      | 320 ms       | 379 ms       |


The next table shows the operation timings on CPU when the left input is encrypted and the right is a clear scalar of the same size:

| Operation \ Size                                       | `FheUint8` | `FheUint16` | `FheUint32` | `FheUint64` | `FheUint128` | `FheUint256` |
|--------------------------------------------------------|------------|-------------|-------------|-------------|--------------|--------------|
| Add / Sub (`+`,`-`)                                    | 75.9 ms    | 95.3 ms     | 119 ms      | 150 ms      | 182 ms       | 224 ms       |
| Mul (`x`)                                              | 79.3 ms    | 163 ms      | 211 ms      | 273 ms      | 467 ms       | 1.09 s       |
| Equal / Not Equal (`eq`, `ne`)                         | 31.2 ms    | 30.9 ms     | 34.4 ms     | 54.5 ms     | 57.0 ms      | 58.0 ms      |
| Comparisons  (`ge`, `gt`, `le`, `lt`)                  | 38.6 ms    | 56.3 ms     | 76.1 ms     | 99.0 ms     | 124 ms       | 141 ms       |
| Max / Min   (`max`,`min`)                              | 74.0 ms    | 103 ms      | 122 ms      | 144 ms      | 171 ms       | 214 ms       |
| Bitwise operations (`&`, `\|`, `^`)                    | 19.0 ms    | 19.8 ms     | 20.5 ms     | 21.6 ms     | 23.8 ms      | 25.8 ms      |
| Div  (`/`)                                             | 192 ms     | 255 ms      | 322 ms      | 459 ms      | 877 ms       | 2.61 s       |
| Rem  (`%`)                                             | 336 ms     | 482 ms      | 650 ms      | 871 ms      | 1.39 s       | 3.05 s       |
| Left / Right Shifts (`<<`, `>>`)                       | 19.5 ms    | 20.2 ms     | 20.7 ms     | 22.1 ms     | 23.8 ms      | 25.6 ms      |
| Left / Right Rotations (`left_rotate`, `right_rotate`) | 19.0 ms    | 20.0 ms     | 20.8 ms     | 21.7 ms     | 23.9 ms      | 25.7 ms      |

All timings are based on parallelized Radix-based integer operations where each block is encrypted using the default parameters `PARAM_MESSAGE_2_CARRY_2_KS_PBS`. To ensure predictable timings, we perform operations in the `default` mode, which ensures that the input and output encoding are similar (i.e., the carries are always emptied). 

You can minimize operational costs by selecting from 'unchecked', 'checked', or 'smart' modes from [the fine-grained APIs](../../references/fine-grained-apis/quick_start.md), each balancing performance and correctness differently.
For more details about parameters, see [here](../../references/fine-grained-apis/shortint/parameters.md). You can find the benchmark results on GPU for all these operations [here](../../guides/run\_on\_gpu.md#benchmarks).

## Programmable bootstrapping
The next table shows the execution time of a keyswitch followed by a programmable bootstrapping depending on the precision of the input message. The associated parameter set is given.
The configuration is Concrete FFT + AVX-512.

## Shortint operations

The next table shows the execution time of some operations using various parameter sets of tfhe-rs::shortint. Except for `unchecked_add`, we perform all the operations in the `default` mode. This mode ensures predictable timings along the entire circuit by clearing the carry space after each operation. The configuration is Concrete FFT + AVX-512.

| Precision                          | 2 bits                        | 4 bits                         | 6 bits                        | 8 bits                        |
| `Parameter set`                    | `PARAM\_MESSAGE\_1\_CARRY\_1` | ``PARAM\_MESSAGE\_2\_CARRY\_2` | `PARAM\_MESSAGE\_3\_CARRY\_3` | `PARAM\_MESSAGE\_4\_CARRY\_4` |
|------------------------------------|-------------------------------|--------------------------------|-------------------------------|-------------------------------|
| keyswitch\_programmable\_bootstrap | 9.85 ms                       | 13.9 ms                        | 114 ms                        | 791 ms                        |


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

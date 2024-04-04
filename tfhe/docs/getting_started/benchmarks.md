# Benchmarks

Due to their nature, homomorphic operations are naturally slower than their cleartext equivalents. Some timings are exposed for basic operations. For completeness, benchmarks for other libraries are also given.

{% hint style="info" %}
All benchmarks were launched on an AWS hpc7a.96xlarge instance with the following specifications: AMD EPYC 9R14 CPU @ 2.60GHz and 740GB of RAM.
{% endhint %}

## Integer

This measures the execution time for some operation sets of tfhe-rs::integer (the unsigned version). Note that the timings for `FheInt` (i.e., the signed integers) are similar.

The table below reports the timing when the inputs of the benchmarked operation are encrypted.

| Operation \ Size                                       | `FheUint8` | `FheUint16` | `FheUint32` | `FheUint64` | `FheUint128` | `FheUint256` |
| ------------------------------------------------------ | ---------- | ----------- | ----------- | ----------- | ------------ | ------------ |
| Negation (`-`)                                         | 55.2 ms    | 80.4 ms     | 104 ms      | 130 ms      | 161 ms       | 202 ms       |
| Add / Sub (`+`,`-`)                                    | 57.7 ms    | 82.1 ms     | 105 ms      | 128 ms      | 155 ms       | 195 ms       |
| Mul (`x`)                                              | 80.8 ms    | 149 ms      | 211 ms      | 366 ms      | 961 ms       | 3.2 s        |
| Equal / Not Equal (`eq`, `ne`)                         | 31.9 ms    | 31.3 ms     | 48.7 ms     | 50.9 ms     | 51.4 ms      | 52.8 ms      |
| Comparisons  (`ge`, `gt`, `le`, `lt`)                  | 48.1 ms    | 68.4 ms     | 83.2 ms     | 102 ms      | 121 ms       | 145 ms       |
| Max / Min   (`max`,`min`)                              | 81.1 ms    | 96.4 ms     | 114 ms      | 133 ms      | 154 ms       | 198 ms       |
| Bitwise operations (`&`, `\|`, `^`)                    | 15.9 ms    | 16.1 ms     | 16.7 ms     | 17.8 ms     | 19.1 ms      | 21.9 ms      |
| Div / Rem  (`/`, `%`)                                  | 613 ms     | 1.56 s      | 3.73 s      | 8.83 s      | 20.6 s       | 53.8 s       |
| Left / Right Shifts (`<<`, `>>`)                       | 88.1 ms    | 108 ms      | 133 ms      | 160 ms      | 199 ms       | 403 ms       |
| Left / Right Rotations (`left_rotate`, `right_rotate`) | 83.6 ms    | 101 ms      | 127 ms      | 158 ms      | 198 ms       | 402 ms       |
| Leading / Trailing zeros/ones                          | 85.7 ms    | 135 ms      | 151 ms      | 206 ms      | 250 ms       | 308 ms       |
| Log2                                                   | 98.0 ms    | 151 ms      | 173 ms      | 231 ms      | 279 ms       | 333 ms       |

The table below reports the timing when the left input of the benchmarked operation is encrypted and the other is a clear scalar of the same size.

| Operation \ Size                                       | `FheUint8` | `FheUint16` | `FheUint32` | `FheUint64` | `FheUint128` | `FheUint256` |
| ------------------------------------------------------ | ---------- | ----------- | ----------- | ----------- | ------------ | ------------ |
| Add / Sub (`+`,`-`)                                    | 61.7 ms    | 81.0 ms     | 99.3 ms     | 117 ms      | 144 ms       | 189 ms       |
| Mul (`x`)                                              | 62.7 ms    | 133 ms      | 173 ms      | 227 ms      | 371 ms       | 917 ms       |
| Equal / Not Equal (`eq`, `ne`)                         | 33.2 ms    | 32.2 ms     | 31.4 ms     | 49.1 ms     | 49.8 ms      | 51.6 ms      |
| Comparisons  (`ge`, `gt`, `le`, `lt`)                  | 32.1 ms    | 51.9 ms     | 70.8 ms     | 89.2 ms     | 110 ms       | 130 ms       |
| Max / Min   (`max`,`min`)                              | 69.9 ms    | 88.8 ms     | 107 ms      | 130 ms      | 153 ms       | 188 ms       |
| Bitwise operations (`&`, `\|`, `^`)                    | 16.1 ms    | 16.3 ms     | 17.2 ms     | 18.2 ms     | 19.6 ms      | 22.1 ms      |
| Div  (`/`)                                             | 160 ms     | 194 ms      | 275 ms      | 391 ms      | 749 ms       | 2.02 s       |
| Rem  (`%`)                                             | 281 ms     | 404 ms      | 533 ms      | 719 ms      | 1.18 s       | 2.76 s       |
| Left / Right Shifts (`<<`, `>>`)                       | 16.0 ms    | 16.2 ms     | 16.7 ms     | 17.9 ms     | 19.2 ms      | 21.8 ms      |
| Left / Right Rotations (`left_rotate`, `right_rotate`) | 16.4 ms    | 16.6 ms     | 17.2 ms     | 18.4 ms     | 19.7 ms      | 22.2 ms      |

All timings are related to parallelized Radix-based integer operations, where each block is encrypted using the default parameters (i.e., PARAM\_MESSAGE\_2\_CARRY\_2\_KS\_PBS, more information about parameters can be found [here](../references/fine-grained-apis/shortint/parameters.md)). To ensure predictable timings, the operation flavor is the `default` one: the carry is propagated if needed. The operation costs may be reduced by using `unchecked`, `checked`, or `smart`.

## Shortint

This measures the execution time for some operations using various parameter sets of tfhe-rs::shortint. Except for `unchecked_add`, all timings are related to the `default` operations. This flavor ensures predictable timings for an operation along the entire circuit by clearing the carry space after each operation.

This uses the Concrete FFT + AVX-512 configuration.

| Parameter set                      | PARAM\_MESSAGE\_1\_CARRY\_1 | PARAM\_MESSAGE\_2\_CARRY\_2 | PARAM\_MESSAGE\_3\_CARRY\_3 | PARAM\_MESSAGE\_4\_CARRY\_4 |
| ---------------------------------- | --------------------------- | --------------------------- | --------------------------- | --------------------------- |
| unchecked\_add                     | 341 ns                      | 555 ns                      | 2.47 µs                     | 9.77 µs                     |
| add                                | 5.96 ms                     | 12.6 ms                     | 102 ms                      | 508 ms                      |
| mul\_lsb                           | 5.99 ms                     | 12.3 ms                     | 101 ms                      | 500 ms                      |
| keyswitch\_programmable\_bootstrap | 6.40 ms                     | 12.9 ms                     | 104 ms                      | 489 ms                      |

## Boolean

This measures the execution time of a single binary Boolean gate.

### tfhe-rs::boolean.

| Parameter set                                        | Concrete FFT + AVX-512 |
| ---------------------------------------------------- | ---------------------- |
| DEFAULT\_PARAMETERS\_KS\_PBS                         | 8.49 ms                |
| PARAMETERS\_ERROR\_PROB\_2\_POW\_MINUS\_165\_KS\_PBS | 13.7 ms                |
| TFHE\_LIB\_PARAMETERS                                | 9.90 ms                |

### tfhe-lib.

Using the same hpc7a.96xlarge machine as the one for tfhe-rs, the timings are:

| Parameter set                                    | spqlios-fma |
| ------------------------------------------------ | ----------- |
| default\_128bit\_gate\_bootstrapping\_parameters | 13.5 ms     |

### OpenFHE (v1.1.2).

Following the official instructions from OpenFHE, `clang14` and the following command are used to setup the project: `cmake -DNATIVE_SIZE=32 -DWITH_NATIVEOPT=ON -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DWITH_OPENMP=OFF ..`

To use the HEXL library, the configuration used is as follows:

```bash
export CXX=clang++
export CC=clang

scripts/configure.sh
Release -> y
hexl -> y

scripts/build-openfhe-development-hexl.sh
```

Using the same hpc7a.96xlarge machine as the one for tfhe-rs, the timings are:

| Parameter set                     | GINX    | GINX w/ Intel HEXL |
| --------------------------------- | ------- | ------------------ |
| FHEW\_BINGATE/STD128\_OR          | 25.5 ms | 21,6 ms            |
| FHEW\_BINGATE/STD128\_LMKCDEY\_OR | 25.4 ms | 19.9 ms            |

## How to reproduce TFHE-rs benchmarks

TFHE-rs benchmarks can be easily reproduced from [source](https://github.com/zama-ai/tfhe-rs).

{% hint style="info" %}
AVX512 is now enabled by default for benchmarks when available
{% endhint %}

```shell
#Boolean benchmarks:
make bench_boolean

#Integer benchmarks:
make bench_integer

#Shortint benchmarks:
make bench_shortint
```

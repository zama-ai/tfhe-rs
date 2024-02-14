# Benchmarks

Due to their nature, homomorphic operations are naturally slower than their cleartext equivalents. Some timings are exposed for basic operations. For completeness, benchmarks for other libraries are also given.

{% hint style="info" %}
All benchmarks were launched on an AWS hpc7a.96xlarge instance with the following specifications: AMD EPYC 9R14 CPU @ 2.60GHz and 740GB of RAM.
{% endhint %}

## Integer

This measures the execution time for some operation sets of tfhe-rs::integer (the unsigned version). Note that the timings for `FheInt` (i.e., the signed integers) are similar.

The table below reports the timing when the inputs of the benchmarked operation are encrypted.

| Operation \ Size                                       | `FheUint8` | `FheUint16` | `FheUint32` | `FheUint64` | `FheUint128` | `FheUint256` |
|--------------------------------------------------------|------------|-------------|-------------|-------------|--------------|--------------|
| Negation (`-`)                                         | 55.4 ms    | 79.7 ms     | 105 ms      | 133 ms      | 163 ms       | 199 ms       |
| Add / Sub (`+`,`-`)                                    | 58.9 ms    | 86.0 ms     | 106 ms      | 124 ms      | 151 ms       | 193 ms       |
| Mul (`x`)                                              | 122 ms     | 164 ms      | 227 ms      | 410 ms      | 1,04 s       | 3,41 s       |
| Equal / Not Equal (`eq`, `ne`)                         | 32.0 ms    | 32.0 ms     | 50.4 ms     | 50.9 ms     | 53.1 ms      | 54.6 ms      |
| Comparisons  (`ge`, `gt`, `le`, `lt`)                  | 43.7 ms    | 65.2 ms     | 84.3 ms     | 107 ms      | 132 ms       | 159 ms       |
| Max / Min   (`max`,`min`)                              | 68.4 ms    | 86.8 ms     | 106 ms      | 132 ms      | 160 ms       | 200 ms       |
| Bitwise operations (`&`, `\|`, `^`)                    | 17.1 ms    | 17.3 ms     | 17.8 ms     | 18.8 ms     | 20.2 ms      | 22.2 ms      |
| Div / Rem  (`/`, `%`)                                  | 631 ms     | 1.59 s      | 3.77 s      | 8,64 s      | 20,3 s       | 53,4 s       |
| Left / Right Shifts (`<<`, `>>`)                       | 82.8 ms    | 99.2 ms     | 121 ms      | 149 ms      | 194 ms       | 401 ms       |
| Left / Right Rotations (`left_rotate`, `right_rotate`) | 82.1 ms    | 99.4 ms     | 120 ms      | 149 ms      | 194 ms       | 402 ms       |

The table below reports the timing when the left input of the benchmarked operation is encrypted and the other is a clear scalar of the same size.

| Operation \ Size                                       | `FheUint8` | `FheUint16` | `FheUint32` | `FheUint64` | `FheUint128` | `FheUint256` |
|--------------------------------------------------------|------------|-------------|-------------|-------------|--------------|--------------|
| Add / Sub (`+`,`-`)                                    | 68.3 ms    | 82.4 ms     | 102 ms      | 122 ms      | 151 ms       | 191 ms       |
| Mul (`x`)                                              | 93.7 ms    | 139 ms      | 178 ms      | 242 ms      | 516 ms       | 1.02 s       |
| Equal / Not Equal (`eq`, `ne`)                         | 30.2 ms    | 30.8 ms     | 32.7 ms     | 50.4 ms     | 51.2 ms      | 54.8 ms      |
| Comparisons  (`ge`, `gt`, `le`, `lt`)                  | 47.3 ms    | 69.9 ms     | 96.3 ms     | 102 ms      | 138 ms       | 141 ms       |
| Max / Min   (`max`,`min`)                              | 75.4 ms    | 99.7 ms     | 120 ms      | 126 ms      | 150 ms       | 186 ms       |
| Bitwise operations (`&`, `\|`, `^`)                    | 17.1 ms    | 17.4 ms     | 18.2 ms     | 19.2 ms     | 19.7 ms      | 22.6 ms      |
| Div (`/`)                                              | 160 ms     | 212 ms      | 272 ms      | 402 ms      | 796 ms       | 2.27 s       |
| Rem (`%`)                                              | 315 ms     | 428 ms      | 556 ms      | 767 ms      | 1.27 s       | 2.86 s       |
| Left / Right Shifts (`<<`, `>>`)                       | 16.8 ms    | 16.8 ms     | 17.3 ms     | 18.0 ms     | 18.9 ms      | 22.6 ms      |
| Left / Right Rotations (`left_rotate`, `right_rotate`) | 16.8 ms    | 16.9 ms     | 17.3 ms     | 18.3 ms     | 19.0 ms      | 22.8 ms      |

All timings are related to parallelized Radix-based integer operations, where each block is encrypted using the default parameters (i.e., PARAM\_MESSAGE\_2\_CARRY\_2\_KS\_PBS, more information about parameters can be found [here](../fine_grained_api/shortint/parameters.md)).
To ensure predictable timings, the operation flavor is the `default` one: the carry is propagated if needed. The operation costs may be reduced by using `unchecked`, `checked`, or `smart`.


## Shortint

This measures the execution time for some operations using various parameter sets of tfhe-rs::shortint. Except for `unchecked_add`, all timings are related to the `default` operations. This flavor ensures predictable timings for an operation along the entire circuit by clearing the carry space after each operation.

This uses the Concrete FFT + AVX-512 configuration.

| Parameter set                      | PARAM\_MESSAGE\_1\_CARRY\_1 | PARAM\_MESSAGE\_2\_CARRY\_2 | PARAM\_MESSAGE\_3\_CARRY\_3 | PARAM\_MESSAGE\_4\_CARRY\_4 |
|------------------------------------|-----------------------------|-----------------------------|-----------------------------|-----------------------------|
| unchecked\_add                     | 341 ns                      | 555 ns                      | 2.47 µs                     | 9.77 µs                     |
| add                                | 5.96 ms                     | 12.6 ms                     | 102 ms                      | 508 ms                      |
| mul\_lsb                           | 5.99 ms                     | 12.3 ms                     | 101 ms                      | 500 ms                      |
| keyswitch\_programmable\_bootstrap | 6.40 ms                     | 12.9 ms                     | 104 ms                      | 489 ms                      |


## Boolean

This measures the execution time of a single binary Boolean gate.

### tfhe-rs::boolean.

| Parameter set                                        | Concrete FFT + AVX-512 |
|------------------------------------------------------|------------------------|
| DEFAULT\_PARAMETERS\_KS\_PBS                         | 8.49 ms                |
| PARAMETERS\_ERROR\_PROB\_2\_POW\_MINUS\_165\_KS\_PBS | 13.7 ms                |
| TFHE\_LIB\_PARAMETERS                                | 9.90 ms                |


### tfhe-lib.

Using the same hpc7a.96xlarge machine as the one for tfhe-rs, the timings are:

| Parameter set                                    | spqlios-fma |
|--------------------------------------------------|-------------|
| default\_128bit\_gate\_bootstrapping\_parameters | 13.5 ms     |

### OpenFHE (v1.1.2).

Following the official instructions from OpenFHE, `clang14` and the following command are used to setup the project:
`cmake -DNATIVE_SIZE=32 -DWITH_NATIVEOPT=ON -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DWITH_OPENMP=OFF ..`

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

| Parameter set                    | GINX    | GINX w/ Intel HEXL |
|----------------------------------|---------|--------------------|
| FHEW\_BINGATE/STD128\_OR         | 25.5 ms | 21,6 ms            |
| FHEW\_BINGATE/STD128\_LMKCDEY_OR | 25.4 ms | 19.9 ms            |


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

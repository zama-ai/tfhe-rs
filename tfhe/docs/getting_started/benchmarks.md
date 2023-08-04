# Benchmarks

Due to their nature, homomorphic operations are naturally slower than their cleartext equivalents. Some timings are exposed for basic operations. For completeness, benchmarks for other libraries are also given.

{% hint style="info" %}
All benchmarks were launched on an AWS m6i.metal with the following specifications: Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz and 512GB of RAM.
{% endhint %}

## Integer

This measures the execution time for some operation sets of tfhe-rs::integer (the unsigned version). Note that the timings for `FheInt` (i.e., the signed integers) are similar.

| Operation \ Size                                       | `FheUint8` | `FheUint16` | `FheUint32` | `FheUint64` | `FheUint128` | `FheUint256` |
|--------------------------------------------------------|------------|-------------|-------------|-------------|--------------|--------------|
| Negation (`-`)                                         | 70.9 ms    | 99.3 ms     | 129 ms      | 180 ms      | 239 ms       | 333 ms       |
| Add / Sub (`+`,`-`)                                    | 70.5 ms    | 100 ms      | 132 ms      | 186 ms      | 249 ms       | 334 ms       |
| Mul (`x`)                                              | 144 ms     | 216 ms      | 333 ms      | 832 ms      | 2.50 s       | 8.85 s       |
| Equal / Not Equal (`eq`, `ne`)                         | 36.1 ms    | 36.5 ms     | 57.4 ms     | 64.2 ms     | 67.3 ms      | 78.1 ms      |
| Comparisons  (`ge`, `gt`, `le`, `lt`)                  | 52.6 ms    | 73.1 ms     | 98.8 ms     | 124 ms      | 165 ms       | 201 ms       |
| Max / Min   (`max`,`min`)                              | 76.2 ms    | 102 ms      | 135 ms      | 171 ms      | 212 ms       | 301 ms       |
| Bitwise operations (`&`, `\|`, `^`)                    | 19.4 ms    | 20.3 ms     | 21.0 ms     | 27.2 ms     | 31.6 ms      | 40.2 ms      |
| Div / Rem  (`/`, `%`)                                  | 729 ms     | 1.93 s      | 4.81 s      | 12.2 s      | 30.7 s       | 89.6 s       |
| Left / Right Shifts (`<<`, `>>`)                       | 99.4 ms    | 129 ms      | 180 ms      | 243 ms      | 372 ms       | 762 ms       |
| Left / Right Rotations (`left_rotate`, `right_rotate`) | 103 ms     | 128 ms      | 182 ms      | 241 ms      | 374 ms       | 763 ms       |


All timings are related to parallelized Radix-based integer operations, where each block is encrypted using the default parameters (i.e., PARAM\_MESSAGE\_2\_CARRY\_2\_KS\_PBS, more information about parameters can be found [here](../fine_grained_api/shortint/parameters.md)).
To ensure predictable timings, the operation flavor is the `default` one: the carry is propagated if needed. The operation costs may be reduced by using `unchecked`, `checked`, or `smart`.


## Shortint

This measures the execution time for some operations using various parameter sets of tfhe-rs::shortint. Except for `unchecked_add`, all timings are related to the `default` operations. This flavor ensures predictable timings for an operation along the entire circuit by clearing the carry space after each operation.

This uses the Concrete FFT + AVX-512 configuration.

| Parameter set                      | PARAM\_MESSAGE\_1\_CARRY\_1 | PARAM\_MESSAGE\_2\_CARRY\_2 | PARAM\_MESSAGE\_3\_CARRY\_3 | PARAM\_MESSAGE\_4\_CARRY\_4 |
|------------------------------------|-----------------------------|-----------------------------|-----------------------------|-----------------------------|
| unchecked\_add                     | 348 ns                      | 413 ns                      | 2.95 µs                     | 12.1 µs                     |
| add                                | 7.59 ms                     | 17.0 ms                     | 121 ms                      | 835 ms                      |
| mul\_lsb                           | 8.13 ms                     | 16.8 ms                     | 121 ms                      | 827 ms                      |
| keyswitch\_programmable\_bootstrap | 7.28 ms                     | 16.6  ms                    | 121 ms                      | 811 ms                      |


## Boolean

This measures the execution time of a single binary Boolean gate.

### tfhe-rs::boolean.

| Parameter set                                        | Concrete FFT + AVX-512 |
|------------------------------------------------------|------------------------|
| DEFAULT\_PARAMETERS\_KS\_PBS                         | 9.19 ms                |
| PARAMETERS\_ERROR\_PROB\_2\_POW\_MINUS\_165\_KS\_PBS | 14.1 ms                |
| TFHE\_LIB\_PARAMETERS                                | 10.0 ms                |


### tfhe-lib.

Using the same m6i.metal machine as the one for tfhe-rs, the timings are:

| Parameter set                                    | spqlios-fma |
|--------------------------------------------------|-------------|
| default\_128bit\_gate\_bootstrapping\_parameters | 15.4 ms     |

### OpenFHE (v1.1.1).

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

Using the same m6i.metal machine as the one for tfhe-rs, the timings are:

| Parameter set                    | GINX    | GINX w/ Intel HEXL |
|----------------------------------|---------|--------------------|
| FHEW\_BINGATE/STD128\_OR         | 40.2 ms | 31.0 ms            |
| FHEW\_BINGATE/STD128\_LMKCDEY_OR | 38.6 ms | 28.4 ms            |


## How to reproduce TFHE-rs benchmarks

TFHE-rs benchmarks can be easily reproduced from [source](https://github.com/zama-ai/tfhe-rs).

```shell
#Boolean benchmarks:
make AVX512_SUPPORT=ON bench_boolean

#Integer benchmarks:
make AVX512_SUPPORT=ON bench_integer

#Shortint benchmarks:
make AVX512_SUPPORT=ON bench_shortint
```

If the host machine does not support AVX512, then turning on `AVX512_SUPPORT` will not provide any speed-up.

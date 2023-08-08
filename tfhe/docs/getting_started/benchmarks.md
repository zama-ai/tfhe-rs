# Benchmarks

Due to their nature, homomorphic operations are naturally slower than their clear equivalent. Some timings are exposed for basic operations. For completeness, benchmarks for other libraries are also given.

{% hint style="info" %}
All benchmarks were launched on an AWS m6i.metal with the following specifications: Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz and 512GB of RAM.
{% endhint %}

## Boolean

This measures the execution time of a single binary Boolean gate.

### tfhe-rs::boolean.

| Parameter set         | Concrete FFT | Concrete FFT + AVX-512 |
| --------------------- | ------------ | ---------------------- |
| DEFAULT\_PARAMETERS   | 8.8ms        | 6.8ms                  |
| TFHE\_LIB\_PARAMETERS | 13.6ms       | 10.9ms                 |

### tfhe-lib.

| Parameter set                                    | fftw   | spqlios-fma |
| ------------------------------------------------ | ------ | ----------- |
| default\_128bit\_gate\_bootstrapping\_parameters | 28.9ms | 15.7ms      |

### OpenFHE.

| Parameter set | GINX  | GINX (Intel HEXL) |
| ------------- | ----- | ----------------- |
| STD\_128      | 172ms | 78ms              |
| MEDIUM        | 113ms | 50.2ms            |


## Integer
This measures the execution time for some operation sets of tfhe-rs::integer.

| Operation \ Size                                       | `FheUint8` | `FheUint16` | `FheUint32` | ` FheUint64` | `FheUint128` | `FheUint256` |
|--------------------------------------------------------|------------|-------------|-------------|--------------|--------------|--------------|
| Negation (`-`)                                         | 80.4 ms    | 106 ms      | 132 ms      | 193 ms       | 257 ms       | 348 ms       |
| Add / Sub (`+`,`-`)                                    | 81.5 ms    | 110 ms      | 139 ms      | 200 ms       | 262 ms       | 355 ms       |
| Mul (`x`)                                              | 150 ms     | 221 ms      | 361 ms      | 928 ms       | 2.90 s       | 10.97 s      |
| Equal / Not Equal (`eq`, `ne`)                         | 39.4 ms    | 40.2 ms     | 61.1 ms     | 66.4 ms      | 74.5 ms      | 85.7 ms      |
| Comparisons  (`ge`, `gt`, `le`, `lt`)                  | 57.5 ms    | 79.6 ms     | 105 ms      | 136 ms       | 174 ms       | 219 ms       |
| Max / Min   (`max`,`min`)                                | 100 ms     | 130 ms      | 163 ms      | 204 ms       | 245 ms       | 338 ms       |
| Bitwise operations (`&`, `|`, `^`)                     | 20.7 ms    | 21.1 ms     | 22.6 ms     | 30.2 ms      | 34.1 ms      | 42.1 ms      |
| Div / Rem  (`/`, `%`)                                  | 1.37 s     | 3.50 s      | 9.12 s      | 23.9 s       | 59.9 s       | 149.2 s      |
| Left / Right Shifts (`<<`, `>>`)                       | 106 ms     | 140 ms      | 202 ms      | 262 ms       | 403 ms       | 827 ms       |
| Left / Right Rotations (`left_rotate`, `right_rotate`) | 105 ms     | 140 ms      | 199 ms      | 263 ms       | 403 ms       | 829 ms       |



All timings are related to parallelized Radix-based integer operations, where each block is encrypted using the default parameters (i.e., PARAM\_MESSAGE\_2\_CARRY\_2, more information about parameters can be found [here](../fine_grained_api/shortint/parameters.md)).
To ensure predictable timings, the operation flavor is the `default` one: the carry is propagated if needed. The operation costs could be reduced by using `unchecked`, `checked`, or `smart`.


## Shortint
This measures the execution time for some operations using various parameter sets of tfhe-rs::shortint.

This uses the Concrete FFT + AVX-512 configuration.

| Parameter set               | unchecked\_add | unchecked\_mul\_lsb | keyswitch\_programmable\_bootstrap |
|-----------------------------|----------------|---------------------|------------------------------------|
| PARAM\_MESSAGE\_1\_CARRY\_1 | 338 ns         | 8.3 ms              | 8.1 ms                             |
| PARAM\_MESSAGE\_2\_CARRY\_2 | 406 ns         | 18.4 ms             | 18.4 ms                            |
| PARAM\_MESSAGE\_3\_CARRY\_3 | 3.06 µs        | 134 ms              | 129.4 ms                           |
| PARAM\_MESSAGE\_4\_CARRY\_4 | 11.7 µs        | 854 ms              | 828.1 ms                           |

Next, the timings for the operation flavor `default` are given. This flavor ensures predictable timings of an operation along the entire circuit by clearing the carry space after each operation.

| Parameter set               |            add |        mul\_lsb     | keyswitch\_programmable\_bootstrap |
| --------------------------- | -------------- | ------------------- | ---------------------------------- |
| PARAM\_MESSAGE\_1\_CARRY\_1 | 7.90 ms        | 8.00 ms             | 8.10 ms                            |
| PARAM\_MESSAGE\_2\_CARRY\_2 | 18.4 ms        | 18.1 ms             | 18.4 ms                            |
| PARAM\_MESSAGE\_3\_CARRY\_3 | 131.5 ms       | 129.5 ms            | 129.4 ms                           |
| PARAM\_MESSAGE\_4\_CARRY\_4 | 852.5 ms       | 839.7 ms            | 828.1 ms                           |

## How to reproduce benchmarks

TFHE-rs benchmarks can easily be reproduced from the [sources](https://github.com/zama-ai/tfhe-rs).

```shell
#Boolean benchmarks:
make bench_boolean

#Integer benchmarks:
make bench_integer

#Shortint benchmarks:
make bench_shortint
```

If the host machine supports AVX-512, then the argument `AVX512_SUPPORT=ON' should be added, e.g.:

```shell
#Integer benchmarks:
make AVX512_SUPPORT=ON bench_integer
```





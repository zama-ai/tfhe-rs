# Benchmarks

Due to their nature, homomorphic operations are obviously slower than their clear equivalent. Some timings are exposed for basic operations. For completeness, some benchmarks of other libraries are also given.

All the benchmarks had been launched on an AWS m6i.metal with the following specifications: Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz and 512GB of RAM.

## Boolean

This measures the execution time of a single binary Boolean gate.

### tfhe-rs::boolean.

| Parameter set         | concrete-fft | concrete-fft + avx512 |
| --------------------- | ------------ | --------------------- |
| DEFAULT\_PARAMETERS   | 8.8ms        | 6.8ms                 |
| TFHE\_LIB\_PARAMETERS | 13.6ms       | 10.9ms                |

### tfhe-lib.

| Parameter set                                    | fftw   | spqlios-fma |
| ------------------------------------------------ | ------ | ----------- |
| default\_128bit\_gate\_bootstrapping\_parameters | 28.9ms | 15.7ms      |

### OpenFHE.

| Parameter set | GINX  | GINX (Intel HEXL) |
| ------------- | ----- | ----------------- |
| STD\_128      | 172ms | 78ms              |
| MEDIUM        | 113ms | 50.2ms            |


## tfhe-rs::shortint.
This measures the execution time for some operations and some parameter sets of shortint.

This uses the concrete-fft + avx512 configuration.

| Parameter set               | unchecked\_add | unchecked\_mul\_lsb | keyswitch\_programmable\_bootstrap |
| --------------------------- | -------------- | ------------------- | ---------------------------------- |
| PARAM\_MESSAGE\_1\_CARRY\_1 | 338 ns         | 8.3 ms              | 8.1 ms                             |
| PARAM\_MESSAGE\_2\_CARRY\_2 | 406 ns         | 18.4 ms             | 18.4 ms                            |
| PARAM\_MESSAGE\_3\_CARRY\_3 | 3.06 µs        | 134 ms              | 129.4 ms                           |
| PARAM\_MESSAGE\_4\_CARRY\_4 | 11.7 µs        | 854 ms              | 828.1 ms                           |

Next, the timings for the operation flavor `default` are given. This flavor ensures predicable timings of an operation all along the circuit by clearing the carry space after each operation.

| Parameter set               |            add |        mul\_lsb     | keyswitch\_programmable\_bootstrap |
| --------------------------- | -------------- | ------------------- | ----------------------------------
| PARAM\_MESSAGE\_1\_CARRY\_1 | 7.9 ms         | 8.0 ms              | 8.1 ms                             |
| PARAM\_MESSAGE\_2\_CARRY\_2 | 18.4 ms        | 18.1 ms             | 18.4 ms                            |
| PARAM\_MESSAGE\_3\_CARRY\_3 | 131.5 ms       | 129.5 ms            | 129.4 ms                           |
| PARAM\_MESSAGE\_4\_CARRY\_4 | 852.5 ms       | 839.7 ms            | 828.1 ms                           |


## tfhe-rs::integer.
This measures the execution time for some operations sets of integer.

All the timings are related to Radix-based integers, where each block is encrypted using PARAM\_MESSAGE\_2\_CARRY\_2.
To ensure predicable timings, the operation flavor is the `default` one: a carry propagation is computed after each operation. Operation cost could be reduced by using `unchecked`, `checked` or `smart`. Operation cost could be reduced by using `unchecked`, `checked` or `smart`.

| Plaintext size     |  add           | mul                 | greater\_than (gt) |  min   |
| -------------------| -------------- | ------------------- | ---------          | -------|
| 8    bits          | 406 ns         | 18.4 ms             | 18.4 ms            |        |
| 16   bits          | 3.06 µs        | 134 ms              | 134 ms             |        |
| 32   bits          | 11.7 µs        | 854 ms              | 945 ms             |        |
| 40   bits          | 11.7 µs        | 854 ms              | 945 ms             |        |
| 64   bits          | 11.7 µs        | 854 ms              | 945 ms             |        |
| 128  bits          | 11.7 µs        | 854 ms              | 945 ms             |        |
| 256  bits          | 11.7 µs        | 854 ms              | 945 ms             |        |

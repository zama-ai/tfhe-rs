# Benchmarks

Due to their nature, homomorphic operations are obviously slower than their clear equivalent. In what follows, some timings are exposed for the basic operations. For completeness, some benchmarks of other libraries are also given.

All the benchmarks had been launched on an AWS m6i.metal with the following specifications:
Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz and 512GB of RAM.

## Booleans

This measures the execution time of a single binary boolean gate.

### thfe.rs::booleans

| Parameter set | concrete-fft | concrete-fft + avx512 |
| --- | --- | --- |
| DEFAULT_PARAMETERS | 8.8ms | 6.8ms |
| TFHE_LIB_PARAMETERS | 13.6ms | 10.9ms |

### tfhe-lib

| Parameter set  | fftw | spqlios-fma|
| --- | --- | --- |
| default_128bit_gate_bootstrapping_parameters | 28.9ms | 15.7ms |

### OpenFHE

| Parameter set  | GINX | GINX (Intel HEXL) |
| --- | --- | --- |
| STD_128 | 172ms | 78ms |
| MEDIUM | 113ms | 50.2ms |

## Shortints
This measures the execution time for some operations and some parameter sets of shortints.

### thfe.rs::shortint
This uses the concrete-fft + avx512 configuration.


| Parameter set                    | unchecked_add  |  unchecked_mul_lsb       |  keyswitch_programmable_bootstrap     |
| ---                     | ---            | ---                      | ---                      |
| PARAM_MESSAGE_1_CARRY_1 | 337 ns         | 10.1 ms                  | 9.91 ms                   |
| PARAM_MESSAGE_2_CARRY_2 | 407 ns         | 21.7 ms                  | 21.4 ms                    |
| PARAM_MESSAGE_3_CARRY_3 | 3.06 µs        | 161  ms                  | 159 ms                     |
| PARAM_MESSAGE_4_CARRY_4 | 11.7 µs        | 1.03 s                   | 956 ms                     |

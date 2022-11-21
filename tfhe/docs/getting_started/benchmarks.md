# Benchmarks

Due to their nature, homomorphic operations are obviously slower than their clear equivalent. In what follows, some timings are exposed for basic operations. For completeness, some benchmarks of other libraries are also given.

All the benchmarks had been launched on an AWS m6i.metal with the following specifications: Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz and 512GB of RAM.

## Booleans

This measures the execution time of a single binary boolean gate.

### tfhe.rs::booleans.

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

## Shortint

This measures the execution time for some operations and some parameter sets of shortint.

<<<<<<< HEAD
### tfhe.rs::shortint.
=======
### thfe.rs::shortint.
>>>>>>> b89ca6f (chore(doc): language edits)

This uses the concrete-fft + avx512 configuration.

| Parameter set               | unchecked\_add | unchecked\_mul\_lsb | keyswitch\_programmable\_bootstrap |
| --------------------------- | -------------- | ------------------- | ---------------------------------- |
| PARAM\_MESSAGE\_1\_CARRY\_1 | 338 ns         | 8.3 ms              | 8.1 ms                             |
| PARAM\_MESSAGE\_2\_CARRY\_2 | 406 ns         | 18.4 ms             | 18.4 ms                            |
| PARAM\_MESSAGE\_3\_CARRY\_3 | 3.06 µs        | 134 ms              | 134 ms                             |
| PARAM\_MESSAGE\_4\_CARRY\_4 | 11.7 µs        | 854 ms              | 945 ms                             |

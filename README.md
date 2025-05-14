# Artifact:TFHE Gets Real: an Efficient and Flexible Homomorphic Floating-Point Arithmetic


## Description


In what follows, we provide instructions on how to run the benchmarks from the paper entitled **TFHE Gets Real: An Efficient and Flexible Homomorphic Floating-Point Arithmetic**.
In particular, the benchmarks presented in **Table 5**, **Table 6**, **Table 7**, and the experiments shown in **Table 8** can be easily reproduced using this code. The implementation of the techniques described in the aforementioned paper has been integrated into the **TFHE-rs** library, version 0.5.0. The modified or added source files are organized into two different paths.

The Minifloats (Section 3.1) are located in *tfhe/src/float-wopbs*
- Test files are located in *tfhe/src/float_wopbs/server_key/tests.rs*
- Benchmarks are located in *tfhe/benches/float_wopbs/bench.rs*


The homomorphic floating points (Section 3.2) are located in *tfhe/concrete-float/*
- Test files are located *tfhe/concrete-float/src/server_key/tests.rs*
- Benchmarks are located in *tfhe/concrete-float/benches/bench.rs*


## Dependencies

Tested on Linux and Mac OS with Rust version >= 1.80 (see [here](https://www.rust-lang.org/tools/install) a guide to install Rust).
Complete list of dependencies and a guide on how to install TFHE-rs can be found in the online documentation [here](https://docs.zama.ai/tfhe-rs/0.5-3/getting-started/installation) or in the local file [here](./README_TFHE-rs.md).

## How to run benchmarks
At the root of the project (i.e., in the TFHE-rs folder), enter the following commands to run the benchmarks:

- ```make bench_minifloat```: returns the timings associated to the Minifloats (**Table 6**).
- ```make bench_float```: returns the timings associated to the HFP (**Table 5**, **Table 7**).
These benchmarks first launch the parallelized and then the sequential experiments. 
This outputs the timings depending on the input precision. 
**This takes more than 6 hours to run**.

To run benchmarks for a specific precision over homomorphic floating points, here are the dedicated commands:
- ```make bench_float_8bit```: Runs benchmarks for only 8-bit floating point *(around 15 min)*.
- ```make bench_float_16bit```: Runs benchmarks for only 16-bit floating point *(around 30 min)*.
- ```make bench_float_32bit```: Runs benchmarks for only 32-bit floating point *(around 1h40)*.
- ```make bench_float_64bit```: Runs benchmarks for only 64-bit floating point *(around 6h30)*.


We recall that the benchmarks were performed on AWS using an **m6i.metal** instance with an Intel Xeon 8375C (Ice Lake) processor running at 3.5 GHz, 128 vCPUs, and 512 GiB of memory.

### Understanding Benchmark Output (Criterion.rs)

This project uses [Criterion.rs](https://docs.rs/criterion/latest/criterion/) for benchmarking. Criterion is a powerful and statistically robust benchmarking framework for Rust, and it may produce outputs that are unfamiliar at first glance. This section explains how to interpret them.

#### Sample Output Structure

A typical benchmark result looks like this:

```
test_float             time:   [53.2 µs 54.0 µs 54.8 µs]
                        change: [+0.2% +1.0% +1.8%] (p = 0.002)
Found 3 outliers among 100 measurements (3.00%)
  3 (3.00%) high mild
```

**Here's what this means:**

- `time: [low est.  median  high est.]`: The estimated execution time of the function.
- `change`: The performance change compared to a previous run (if available).
- `outliers`: Some runs deviated from the typical time. Criterion detects and accounts for these using statistical methods.

---

####  Common Warnings and What They Mean

##### `Found X outliers among Y measurements`

Criterion runs each benchmark many times (default: 100) to get statistically significant results.
An *outlier* is a run that was significantly faster or slower than the others.

- **Why does this happen?** Often, it's due to **other processes on the machine** (e.g., background services, OS interrupts, or CPU scheduling) affecting performance temporarily.
- **Why it doesn't invalidate results:** Criterion uses statistical techniques to minimize the impact of these outliers when estimating performance.
- **Best practice to reduce outliers:** Run the benchmarks on a **freshly rebooted machine**, with as few background processes as possible. Ideally, let the system idle for a minute after boot to stabilize before running benchmarks.

##### `Unable to complete 100 samples in 5.0s.`

The benchmark took longer than the expected 5 seconds.
This is merely a warning indicating that the full set of 100 samples could not be collected within the default 5-second measurement window.

- **No action is required**: Criterion will still proceed to run all 100 samples, and the results remain statistically valid.
- **Why the warning appears**: It's there to inform you that benchmarking is taking longer than expected and to help you tune settings if needed.
- **Optional**: If you're constrained by time (e.g., running in CI), you can:
  - Reduce the sample size (e.g., to 10 or 20 samples).
  - Or increase the measurement time using:
    ```bash
    cargo bench -- --measurement-time 30
    ```

## How to run the tests
### MiniFloats

To run the tests related to the **minifloats**, run the following command:
- ```make test_minifloat```: Runs a bivariate operation between two minifloats.


The **minifloat** test is available in the file *tfhe/src/float_wopbs/server_key/tests.rs*.



### Homomorphic Floating Points 
At the root of the project (i.e., in the TFHE-rs folder), enter the following commands to run the tests per operation on the **homomorphic floating points**:
- ```make test_float_add```: Runs a 32-bit floating-point addition with two random inputs.
- ```make test_float_sub```: Runs a 32-bit floating-point subtraction with two random inputs.
- ```make test_float_mul```: Runs a 32-bit floating-point multiplication with two random inputs.
- ```make test_float_div```: Runs a 32-bit floating-point division with two random inputs.
- ```make test_float_cos```: Runs the experiment from **Table 8** with a random input value.
- ```make test_float_sin```: Runs the experiment from **Table 8** with a random input value.
- ```make test_float_relu```: Runs a 32-bit floating-point relu with a random input.
- ```make test_float_sigmoid```: Runs a 32-bit floating-point sigmoid with a random input.
- ```make test_float```: Runs all previous tests for operations on 32-bit floating-points.
- ```make test_float_depth_test```: This command runs the following experiment:
  - **Step 1**: Create 3 blocks, each composed of a clear 32-bit floating point, a clear 64-bit floating point, and a 32-bit homomorphic floating point.
  - **Step 2**: Choose two blocks randomly among the 3 blocks and randomly select a parallelized operation (addition, subtraction, or multiplication).
  - **Step 3**: Compute the selected operation between the two selected blocks and store the result randomly in one of the two selected blocks.  
  (The operation is performed respectively between the two 64-bit floating points, the two 32-bit floating points, and homomorphically between the two 32-bit homomorphic floating points.) 
  - Repeat Steps 2 and 3 for 50 iterations.
  - To avoid reaching + or - infinity, or **NaN**, when the clear 64-bit floating point reaches a fixed bound, compute a multiplication to rescale the value close to 1.  
  This operation is also performed homomorphically for the encrypted data. This test takes several minutes.

The tests are located in the file *tfhe/concrete-float/src/server_key/tests.rs*.

Due to the representation being close to, but not exactly the same as, a given representation, the obtained result is not identical to the one obtained in clear.
To consider a test as "passed", we accept a difference of less than 0.1% compared to the 64-bit floating-point clear results.
Note that using 8 or 16-bit homomorphic floating points might return errors due to a lack of precision and due to the comparisons with clear 64-bit floating points.

In each test, the different results are presented in the following format:
``` 
--------------------
"Name":

Result       : 
Clear 32-bits: 
Clear 64-bits: 

--------------------
```
where ```name``` stands for the name of the ciphertext or the name of the operation, result always corresponds to the decryption of a homomorphic floating point, and Clear ``` 32-bits```  and Clear ``` 64-bits``` correspond to the clear floating-point witness.

All tests in *tfhe/concrete-float/src/server_key/tests.rs* are conducted for 32-bit floating-point precision, as it provides the best ratio between execution time and precision.  
To change the parameter set used, the parameters in the following ``` const ``` must be uncommented (lines 79 to 87 in the file *tfhe/concrete-float/src/server_key/tests.rs*).


```rust 
const PARAMS: [(&str, Parameters); 1] =
[
//named_param!(PARAM_FP_64_BITS),
named_param!(PARAM_FP_32_BITS),
//named_param!(PARAM_FP_16_BITS),
//named_param!(PARAM_FP_8_BITS),
];
```

Note that the number in ``` [(\&str, Parameters); 1] ``` should correspond to the number of tested parameters, e.g., if another parameter sets is uncommented, this line becomes:  ``` [(\&str, Parameters); 2] ```.
The parameter ```PARAM_X``` corresponds to the parameters used in **Table 5**, and ```PARAM_TCHES_X``` corresponds to the parameters used in **Table 7**.





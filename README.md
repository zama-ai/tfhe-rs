# Artifact: Accelerating TFHE with Sorted-Bootstrapping Techniques


## Description

In what follows, we provide instructions on how to run the benchmarks given in **Table 3** (page 29), from the paper titled **Accelerating TFHE with Sorted Bootstrapping Techniques**.
The implementation of the techniques described in the aforementioned paper has been integrated into the **TFHE-rs** library, version `0.8.0-alpha.2`.
The code related to the  extended PBS (EBS), the sorted PBS (SBS) and the version with the companion modulus switch are located in ```tfhe/src/core_crypto/fft_impl/fft64/crypto/bootstrap.rs```.
All the benchmarks can be found in ```tfhe/benches/core_crypto/pbs_bench.rs```.


## Setup and Dependencies

Tested on Linux and macOS with Rust version ≥ 1.85 (we recommend installing Rust via [rustup](https://www.rust-lang.org/tools/install), as rustup is required later by the provided Makefile).
The complete list of dependencies and a guide on how to install TFHE-rs can be found in the online documentation [here](https://docs.zama.ai/tfhe-rs/0.8) or in the local file [here](./README-TFHE-rs.md).

## How to run benchmarks
The benchmarks run across all precision and all failure probabilities, progressing from lower precision (4 bits) to higher precision (9 bits) and from higher failure probabilities ($2^{-64}$) to the lower failure probabilities ($2^{-128}$). 
All the following benchmarks are **sequential**.
At the root of the project (i.e., in the TFHE-rs folder), enter the following commands to run the different benchmarks:

- ```make bench_ly```: returns the timings associated with the extended PBS (EBS[LY23] in **Table 3**).
- ```make bench_sorted```: returns the timings associated with the sorted PBS  (SBS in **Table 3**).
- ```make bench_cms```: returns the timings associated with the SBS with the companion modulus switch (cms) (SBS + CMS in **Table 3**).


To modify the performed benchmarks, only a few lines need to be commented and modified in ```tfhe/benches/core_crypto/pbs_bench.rs```.
To focus only on specific benchmarks, you only need to keep the wanted precision and failure probabilities and adjust the number of tests with ```[ParametersLY23; X]```, where `X` must be equal to the number of uncommented parameters.

All parameter sets follow a syntax of the form: ```{Name}_{Precision}_{-Log2(pfail)}```. 
For instance,  ```LY_5_64``` means that the parameter set is associated to the algorithm referred as *LY* in the paper, with *5* bits of precision for input message and $2^{-64}$ as failure probability.

For the EBS and the SBS, you need to modify lines 1502 to 1507 and lines 1612 to 1616 for the SBS with CMS.
For instance, changing lines 1502 to 1507:
```rust 
const PARAM_BENCHES_LY23: [ParametersLY23; 16] = [
  //LY_5_40, LY_6_40, LY_7_40, LY_8_40, LY_9_40
  LY_5_64, LY_6_64, LY_7_64, LY_8_64, LY_9_64,
  LY_5_80, LY_6_80, LY_7_81, LY_8_81, LY_9_81,
  LY_4_128, LY_5_128, LY_6_129, LY_7_128, LY_8_128, LY_9_129,
];
```
into:
```rust 
const PARAM_BENCHES_LY23: [ParametersLY23; 6] = [
  //LY_5_40, LY_6_40, LY_7_40, LY_8_40, LY_9_40,
  //LY_5_64, LY_6_64, LY_7_64, LY_8_64, LY_9_64,
  //LY_5_80, LY_6_80, LY_7_81, LY_8_81, LY_9_81,
  LY_4_128, LY_5_128, LY_6_129, LY_7_128, LY_8_128, LY_9_129,
];
```
and using the command  ```make bench_ly``` launches only benchmarks for the EBS experiment with a failure probability of $2^{-128}$.


### Sample Output Structure

A typical benchmark result looks like this:

```
KS_Extended_PBS_LY23/PRECISION_6_BITS__EXTENDED_FACTOR_2^2__PFAIL_2^-64
time:   [123.38 ms 123.46 ms 123.55 ms]
Found 19 outliers among 500 measurements (3.80%)
```

The first line indicates the operation whose latency is measured.

**Examples:**
```
KS_Extended_PBS_LY23/PRECISION_6_BITS__EXTENDED_FACTOR_2^2__PFAIL_2^-64 
```
means that this benchmark is measuring the latency of a Keyswitch (KS) followed by an Extended Bootstrapping (EBS [LY23]) with 6 bits of message, an extended factor equal to $2^2$, and a failure probability pfail $=2^{-64}$.

#### Understanding Benchmark Output (Criterion.rs)
This project uses Criterion.rs for benchmarking. Criterion is a powerful and statistically robust benchmarking framework for Rust, and it may produce outputs that are unfamiliar at first glance. Here is a short explanation:

    time: [low est.  median  high est.]: The estimated execution time of the function.
    change: The performance change compared to a previous run (if available).
    outliers: Some runs deviated from the typical time. Criterion detects and accounts for these using statistical methods.


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

## Other Experiments (See long-paper version)
This section explains how to run more benchmarks related to the paper results appearing in the long version.
At the root of the project, run:

- ```make bench_pbs_asiacrypt```: returns the timings associated to the vanilla PBS. Can be used as another baseline comparison to see the impact of the EBS, SBS and SBS+CMS.

- ```make bench_ly23_parallelized```: returns the timings associated to the parallelized version of the extended PBS (EBS) from LY.
- ```make bench_sorted_parallelized```: returns the timings associated to the parallelized sorted PBS (SBS).

These benchmarks can be used to see the impact of the sorted PBS in a parallelized context.

As with the previous benchmarks, the launched experiment can be modified to only be performed on the wanted precision and failure probabilities by changing lines 1619 to 1628 for the PBS and lines 1630 to 1663 for the parallelized version.

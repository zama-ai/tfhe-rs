# Artifact: Sharing the Mask: TFHE Bootstrapping on Packed Messages

## Description
This artifact contains source files to reproduce the benchmarks and security estimates of the paper entitled **Sharing the Mask: TFHE Bootstrapping on Packed Messages**.

### Source Files and Benchmarks
In what follows, we provide instructions on how to run the benchmarks from the paper.  
This allows users to reproduce the experimental results presented in Table 3 and Table 4.
The implementation extends the **TFHE-rs** library (v1.3.0).
Source files related to the implementation of the "Common Mask" technique are prefixed by *cm_*, and can be found here in ```tfhe/src/core_crypto/algorithms/``` and ```tfhe/src/core_crypto/entities/```.


### Security estimates of the parameter sets
We provide a script to reproduce the security estimates of the parameter sets (**Tables 8-13**) based on the lattice-estimator. This gives the security evaluations regarding the attacks **usvp**, **bdd**, **dual**, **dual-hybrid** and **bdd-hybrid** (as displayed on **Table 13**), but for all parameter sets.
In the paper, except in the Table 13, only the minimum value among all the evaluations is given as an output.
The script called ```estimates.py``` is in the ```security_estimates``` folder.

## Benchmarks 
## Setup and Dependencies 
Tested on Linux and macOS with Rust version ≥ 1.85 (we recommend installing Rust via [rustup](https://www.rust-lang.org/tools/install), as rustup is required later by the provided Makefile).
The complete list of dependencies and a guide on how to install TFHE-rs can be found in the online documentation [here](https://docs.zama.ai/tfhe-rs/1.3/getting-started/installation) or in the local file [here](./README_TFHE-rs.md).

## How to run benchmarks
At the root of the project (i.e., in the TFHE-rs folder), enter the following commands to run the benchmarks:
- ```make bench_common_mask_bootstrapping```: this outputs the latency related to the CM bootstrapping for all precision, number of bodies and failure probabilities used in the paper;
- ```make bench_bootstrapping```: this outputs the latency related to the reference bootstrapping for all precision and failure probabilities used in the paper.

The benchmark files are in ```tfhe-benchmark/benches/core_crypto/cm_bench.rs``` (for the ones related to the common mask bootstrapping) and ```tfhe-benchmark/benches/shortint/standard_ap.rs``` (for the ones related to the usual bootstrapping). 

*WARNING*: Benchmarks were executed on an **AWS `hpc7a.96xlarge` instance** equipped with an **AMD EPYC 9R14 CPU @ 2.60GHz** and **740 GB of memory**.
To prevent potential crashes due to memory limitations, **parameter sets involving large precision and/or high sample counts are disabled by default**.

*To Enable All Benchmarks:*
- For **`pfail < 2^{-64}`**, uncomment lines **[23–29]**
- For **`pfail < 2^{-128}`**, uncomment lines **[48–54]**


### Sample Output Structure
A typical benchmark result looks like this:
```
Common Mask Benchmarks/KS-PBS_p=2_pfail=2-64
                        time:   [9.6238 ms 9.6390 ms 9.6688 ms]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high mild
```

#### Here's what this means:
The first line indicates the operation whose the latency is measured. The legends are:
```{Operations}_p={Precision}_w={Number of Slots}__pfail={Failure Probability} ```, for the CM-based bootstrapping;
```{Operations}_p={Precision}_pfail={Failure Probability} ```, for the reference bootstrapping.

**Examples:**
- ```KS->PBS_p=2_pfail=2-64``` means that this benchmark is measuring the latency of a ```KS->PBS``` i.e., a keyswitch followed by a bootstrapping, with the precision ```p=2``` and a failure probability ```p_fail=2^{-64}```. 
- ```KS->CM-PBS_p=2_w=2_pfail=2-64``` means that this benchmark is measuring the latency of a ```CM-KS->CM-PBS``` i.e., a CM-based keyswitch followed by a CM-based bootstrapping, with the precision *p=2*, two slots *w=2* and a failure probability ```p_fail=2^{-64}```. 

#### Understanding Benchmark Output (Criterion.rs)
This project uses [Criterion.rs](https://docs.rs/criterion/latest/criterion/) for benchmarking. Criterion is a powerful and statistically robust benchmarking framework for Rust, and it may produce outputs that are unfamiliar at first glance. Here is a short explanation:
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
To run the correctness tests, use the following command: ```make test_common_mask``` at the root of the project.
These could be useful to get minimal examples of the code without the benchmark overlay.
Here are the main tests:
- Computing a keyswitch: ```tfhe/src/core_crypto/algorithms/test/cm_lwe_keyswitch.rs```
- Computing a bootstrapping: ```tfhe/src/core_crypto/algorithms/test/cm_lwe_programmable_bootstrapping.rs```
- Computing compression: ```tfhe/src/core_crypto/algorithms/test/cm_lwe_compression.rs```

Running these tests should output a green *ok*.

*WARNING*: Tests were executed on an **AWS `hpc7a.96xlarge` instance** equipped with an **AMD EPYC 9R14 CPU @ 2.60GHz** and **740 GB of memory**.
To prevent potential crashes due to memory limitations, **parameter sets involving large precision and/or high sample counts are disabled by default**.

*To Enable more tests:*
In the file ``` ./tfhe/src/core_crypto/algorithms/cm-params.rs```:
- For **`pfail < 2^{-64}`**, uncomment lines **[223–229]** and update the number of items in line **209**;
- For **`pfail < 2^{-128}`**, uncomment lines **[246–252]** and update the number of items in line **232**;




## Security Estimates
## Setup and Dependencies 
To run the script, you need to:
- Install SageMath version >= 9.3 (see installation instructions in [here](https://doc.sagemath.org/html/en/installation/index.html))
- Clone the lattice estimator repository from [here](https://github.com/malb/lattice-estimator) into the *security_estimates* folder, i.e.:
```bash 
  cd security_estimates/
  git clone https://github.com/malb/lattice-estimator.git
  ``` 
  This has been tested with the commit *5ba00f5*.


## How to run the security scripts
From the ```security_estimates``` folder, you just have to run ```sage estimates.py``` from the lattice estimator folder.
The first print from the script appears after ~30s.

By default, the script is going to estimate the security for all parameter sets but **this takes several hours to run**. If only table X has to be reproduced, it is possible to comment all the last lines of the script (```estimates.py```, L277-281) except ```print_table_X```(where ```X``` refers to the table number from paper).

### Sample Output Structure
A typical output from the script is:

``` 
TABLE 8
[(LWEParameters(n=790, q=18446744073709551616, Xs=D(σ=0.50, μ=0.50), Xe=D(σ=140010787519455.50), m=+Infinity, tag=None), [('dual_hybrid', 131.99795566989317), ('usvp', 139.31328486797534), ('dual', 143.72739944730603), ('bdd', 154.85610718083302), ('bdd_hybrid', 348.98671493681695)])]
```


#### Here's what this means:
By splitting in several parts:
- ```LWEParameters(n=790, q=18446744073709551616, Xs=D(σ=0.50, μ=0.50), Xe=D(σ=140010787519455.50), m=+Infinity, tag=None)```: this gives the evaluated parameter sets, the lattice dimension ```n=790```, the modulus ```q=18446744073709551616```, the secret key distribution  ```Xs=D(σ=0.50, μ=0.50)``` (i.e., binary in this case), the error variance of a centered Gaussian distribution ```Xe=D(σ=140010787519455.50)```, the number of samples ```m=+Infinity```;
- ```[('dual_hybrid', 131.99795566989317), ('usvp', 139.31328486797534), ('dual', 143.72739944730603), ('bdd', 154.85610718083302), ('bdd_hybrid', 348.98671493681695)])]```: each tuple gives the considered attack and the logarithm of the attack cost, e.g., for the ```dual_hybrid```, the security estimation is ```131.99795566989317``` bits.


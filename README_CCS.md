# Description
In what follows, we provide instructions on how to run benchmarks from the paper entitled "New Secret Keys for Enhanced Performance in (T)FHE". In particular, Table 2 and Figure 4 (in the Appendix) can be easily reproduced using this code.

The implementation of the techniques from the aforementioned paper has been integrated into the TFHE-rs library, version 0.4.

Modified or added source files are located in `tfhe/src/core_crypto/`:
- `algorithms/pseudo_ggsw_encryption.rs`
- `algorithms/pseudo_ggsw_conversion.rs`
- `algorithms/lwe_shrinking_keyswitch_key_generation.rs`
- `algorithms/lwe_shrinking_keyswitch.rs`
- `algorithms/lwe_secret_key_generation.rs`
- `algorithms/lwe_partial_secret_key_generation.rs`
- `algorithms/lwe_fast_keyswitch_key_generation.rs`
- `algorithms/lwe_fast_keyswitch.rs`
- `algorithms/glwe_secret_key_generation.rs`
- `algorithms/glwe_partial_secret_key_generation.rs`
- `algorithms/glwe_partial_sample_extraction.rs`

Test files are located in `tfhe/src/core_crypto/algorithms/test`:
- `lwe_stair_keyswitch.rs`
- `lwe_fast_keyswitch.rs`

Benchmarks are located in `tfhe/benches/core_crypto`:
- `ccs_2024_cjp.rs`
- `ccs_2024_fft_shrinking_ks.rs`
- `ccs_2024_stair_ks.rs`

# Dependencies
Tested on Linux and Mac OS with Rust >= 1.75 (see [here](https://www.rust-lang.org/tools/install) a guide to install Rust).

# How to run benchmarks
At the root of the project (i.e., in the TFHE-rs folder), enter the following commands to run the benchmarks:
- `make bench_ccs_2024_cjp`: Returns the timings associated with the CJP-based bootstrapping (Table 2, Line 1 + Figure 4, blue line);
- `make bench_ccs_2024_stair_ks`: Returns the timings associated with the "All+Stair-KS"-based bootstrapping (Table 2, Line 2 + Figure 4, red line);
- `make bench_ccs_2024_fft_shrinking_ks`: Returns the timings associated with the "All+FFT Shrinking-KS"-based bootstrapping (Table 2, Line 3 + Figure 4, green line); 

This outputs the timings depending on the input precision.
Since large precision (>= 6 bits) might be long to execute, particularly on a laptop, these are disable by default. To choose which precision to launch, please uncomment lines associated to the parameter names into the `param_vec` variable, inside the `criterion_bench` function inside one of the benchmark files.

For instance, to launch only the precision 7 of the stair-KS benchmark, the correct `param_vec` variable (line 353 of `ccs_2024_stair_ks.rs`) looks like:
```rust 
let param_vec = [
        // PRECISION_1_STAIR,
        // PRECISION_2_STAIR,
        // PRECISION_3_STAIR,
        // PRECISION_4_STAIR,
        // PRECISION_5_STAIR,
        // PRECISION_6_STAIR,
        PRECISION_7_STAIR
        // PRECISION_8_STAIR,
        // PRECISION_9_STAIR,
        // PRECISION_10_STAIR,
        // PRECISION_11_STAIR,
    ];

```
Running the command `make bench_ccs_2024_stair_ks`will give the correct benchmark.


# How to run the tests
At the root of the project (i.e., in the TFHE-rs folder), enter the following commands to run the tests:
- `make test_ccs_2024_stair_ks`: Runs the tests associated with the "All+Stair-KS"-based bootstrapping (Table 2, Line 2 + Figure 4, red line);
- `make test_ccs_2024_fft_shrinking_ks`: Runs the tests associated with the "All+FFT Shrinking-KS"-based bootstrapping (Table 2, Line 3 + Figure 4, green line);

As for the benchmarks, all precision are not enabled by default. To add precision in the test, associated parameters must be uncommented in the macro `create_parametrized_test!` (located at the end of each test file)

For instance, in the file `lwe_fast_keyswitch.rs`, testing only up to precision 8 will look like this:
```rust 
create_parametrized_test!(lwe_encrypt_fast_ks_decrypt_custom_mod {
    PRECISION_1_FAST_KS,
    PRECISION_2_FAST_KS,
    PRECISION_3_FAST_KS,
    PRECISION_4_FAST_KS,
    PRECISION_5_FAST_KS,
    PRECISION_6_FAST_KS,
    PRECISION_7_FAST_KS,
    PRECISION_8_FAST_KS
    //  PRECISION_9_FAST_KS,
    // PRECISION_10_FAST_KS
    // PRECISION_11_FAST_KS
});
```
Please note that the last argument in the macro call MUST NOT be followed by a comma `,` to correctly compile (notice the missing comma after `PRECISION_8_FAST_KS` in the example above).


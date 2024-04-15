# PBS statistics

This document explains how to use the PBS statistics feature in **TFHE-rs'** shortint API to assess the overall computational intensity in FHE applications.

The `shortint` API now includes a global counter to track the number of Programmable Bootstrapping (PBS) executed with the `pbs-stats` feature. This feature enables precise tracking of PBS executions in a circuit. It helps to estimate the overall compute intensity of FHE code using either the `shortint`, `integer,` or High-Level APIs.

To know how many PBSes were executed, call `get_pbs_count`. To reset the PBS count, call `reset_pbs_count`. You can combine two functions to understand how many PBSes were executed in each part of your code.

When combined with the [`debug mode`](../fundamentals/debug.md), this feature allows for quick estimations during iterations on the FHE code.

Here is an example of how to use the PBS counter:

```rust
use tfhe::prelude::*;
use tfhe::*;

pub fn main() {
    // Config and key generation
    let config = ConfigBuilder::default().build();

    let (cks, sks) = generate_keys(config);

    // Encryption
    let a = FheUint32::encrypt(42u32, &cks);
    let b = FheUint32::encrypt(16u32, &cks);

    // Set the server key
    set_server_key(sks);

    // Compute and get the PBS count for the 32 bits multiplication
    let c = &a * &b;
    let mul_32_count = get_pbs_count();

    // Reset the PBS count, and get the PBS count for a 32 bits bitwise AND
    reset_pbs_count();
    let d = &a & &b;
    let and_32_count = get_pbs_count();

    // Display the result
    println!("mul_32_count: {mul_32_count}");
    println!("and_32_count: {and_32_count}");
}

```

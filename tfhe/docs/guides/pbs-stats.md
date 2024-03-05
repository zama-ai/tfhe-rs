# PBS Statistics

The `shortint` API now keeps track of how many PBS were executed with a global counter when enabling the `pbs-stats` feature.

This allows knowing precisely how many PBS are executed in a circuit and estimate the overall compute intensity of FHE code using either the `shortint`, `integer` or High-Level APIs.

You can query how many PBSes were executed by calling `get_pbs_count`. You can reset the PBS count by calling `reset_pbs_count` to more easily know how many PBSes were executed by each part of your code.

Combined with the [`debug mode`](`debug.md`) it can allow to have estimations very quickly while iterating on the FHE code.

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

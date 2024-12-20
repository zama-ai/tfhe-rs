# Parallelized PBS

This document describes the implementation and benefits of parallelized [Programmable Bootstrapping](../getting\_started/security\_and\_cryptography.md) (PBS) in **TFHE-rs**, including code examples for using multi-bit PBS parameters and ensuring deterministic execution.

## Parallelized Programmable Bootstrapping

Programmable Bootstrapping is inherently a sequential operation. However, some [recent results](https://marcjoye.github.io/papers/JP22ternary.pdf) showed that introducing parallelism is feasible at the expense of larger keys, thereby enhancing the performance of PBS. This new PBS is called a multi-bit PBS.

**TFHE-rs** can already perform parallel execution of integer homomorphic operations. Activating this feature can lead to performance improvements, particularly in the case of high core-count CPUs when enough cores are available, or when dealing with operations that require small input message precision.

The following example shows how to use parallelized bootstrapping by choosing multi-bit PBS parameters:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::default()
        .use_custom_parameters(
           tfhe::shortint::parameters::V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64,
        )
        .build();
        
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);
    
    let clear_a = 673u32;
    let clear_b = 6u32;
    let a = FheUint32::try_encrypt(clear_a, &keys)?;
    let b = FheUint32::try_encrypt(clear_b, &keys)?;

    let c = &a >> &b;
    let decrypted: u32 = c.decrypt(&keys);
    assert_eq!(decrypted, clear_a >> clear_b);

    Ok(())
}
```

## Deterministic parallelized Programmable Bootstrapping

By nature, the parallelized PBS might not be deterministic: while the resulting ciphertext will always decrypt to the correct plaintext, the order of the operations could vary, resulting in different output ciphertext. To ensure a consistent ciphertext output regardless of execution order, add the `with_deterministic_execution()` suffix to the parameters.

Here's an example:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::default()
        .use_custom_parameters(
           tfhe::shortint::parameters::V0_11_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64.with_deterministic_execution(),
        )
        .build();
        
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);
    
    let clear_a = 673u32;
    let clear_b = 6u32;
    let a = FheUint32::try_encrypt(clear_a, &keys)?;
    let b = FheUint32::try_encrypt(clear_b, &keys)?;

    let c = &a >> &b;
    let decrypted: u32 = c.decrypt(&keys);
    assert_eq!(decrypted, clear_a >> clear_b);

    Ok(())
}
```

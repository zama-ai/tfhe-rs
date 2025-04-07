# Ternary conditional operations

This document details the ternary operations supported by **TFHE-rs**.

The ternary conditional operator execute conditional instructions in the form `if cond { choice_if_true } else { choice_if_false }`.

| name             | symbol   | type    |
| ---------------- | -------- | ------- |
| Ternary operator | `select` | Ternary |

The syntax is `encrypted_condition.select(encrypted_choice_if_true, encrypted_choice_if_false)`. The valid `encrypted_condition` must be an encryption of 0 or 1.

The following example shows how to perform ternary conditional operations:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheInt32};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Basic configuration to use homomorphic integers
    let config = ConfigBuilder::default().build();

    // Key generation
    let (client_key, server_keys) = generate_keys(config);
    
    let clear_a = 32i32;
    let clear_b = -45i32;
    
    // Encrypting the input data using the (private) client_key
    // FheInt32: Encrypted equivalent to i32
    let encrypted_a = FheInt32::try_encrypt(clear_a, &client_key)?;
    let encrypted_b = FheInt32::try_encrypt(clear_b, &client_key)?;
    
    // On the server side:
    set_server_key(server_keys);
    
    // Clear equivalent computations: 32 > -45
    let encrypted_comp = &encrypted_a.gt(&encrypted_b);
    let clear_res = encrypted_comp.decrypt(&client_key);
    assert_eq!(clear_res, clear_a > clear_b);
    
    // `encrypted_comp` is a FheBool, thus it encrypts a boolean value.
    // This acts as a condition on which the
    // `select` function can be applied on.
    // Clear equivalent computations:
    // if 32 > -45 {result = 32} else {result = -45}
    let encrypted_res = &encrypted_comp.select(&encrypted_a, &encrypted_b);
    
    let clear_res: i32 = encrypted_res.decrypt(&client_key);
    assert_eq!(clear_res, clear_a);
    
    // Ternary conditional also supports operands that are in clear (except for the condition)
    // with the `scalar` prefix
    let encrypted_res = &encrypted_comp.scalar_select(&encrypted_a, clear_b);
    let clear_res: i32 = encrypted_res.decrypt(&client_key);
    assert_eq!(clear_res, clear_a);

    let encrypted_res = &encrypted_comp.scalar_select(clear_a, &encrypted_b);
    let clear_res: i32 = encrypted_res.decrypt(&client_key);
    assert_eq!(clear_res, clear_a);

    // When both possible results are in clear the form to be used is
    let encrypted_res = FheInt32::select(encrypted_comp, clear_a, clear_b);
    let clear_res: i32 = encrypted_res.decrypt(&client_key);
    assert_eq!(clear_res, clear_a);
   
    Ok(())
}
```

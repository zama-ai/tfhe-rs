# Min/Max operations

This document details the min/max operations supported by **TFHE-rs**.

Homomorphic integers support the min/max operations:

| name | symbol | type   |
| ---- | ------ | ------ |
| Min  | `min`  | Binary |
| Max  | `max`  | Binary |

The following example shows how to perform min/max operations:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ConfigBuilder::default().build();
    let (keys, server_keys) = generate_keys(config);
    set_server_key(server_keys);

    let clear_a:u8 = 164;
    let clear_b:u8 = 212;

    let a = FheUint8::try_encrypt(clear_a, &keys)?;
    let b = FheUint8::try_encrypt(clear_b, &keys)?;

    let min = a.min(&b);
    let max = a.max(&b);

    let dec_min : u8 = min.decrypt(&keys);
    let dec_max : u8 = max.decrypt(&keys);

    assert_eq!(dec_min, u8::min(clear_a, clear_b));
    assert_eq!(dec_max, u8::max(clear_a, clear_b));

    Ok(())
}
```

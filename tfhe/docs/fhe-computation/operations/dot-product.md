# Dot Product

This document details the dot product operations supported by **TFHE-rs**.


| name          | symbol         | type   |
|---------------|----------------| ------ |
| Dot Product   | `dot_product`  | Binary |
| Parallel Dot Product | `dot_product_parallel` | Binary |


Currently, the dot product supports the following cases:
- A slice of `FheBool` and a slice of clear values (e.g., `u64`)
- A slice of encrypted unsigned integers and a slice of clear unsigned integers

Both slices must be non-empty and have the same length.

For encrypted unsigned integers, `dot_product_parallel` executes the scalar multiplications concurrently on CUDA worker streams before reducing the products. On other backends it falls back to `dot_product`.

The following example shows how to perform dot product:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, FheUint8};

fn main() {
    let (client_key, server_key) = generate_keys(ConfigBuilder::default());
    set_server_key(server_key);
  
    let a = [true, false, true]
     .into_iter()
     .map(|b| FheBool::encrypt(b, &client_key))
     .collect::<Vec<_>>();
   
    let b = [2u8, 3u8, 4u8];
   
    let result = FheUint8::dot_product(&a, &b);
    let decrypted: u8 = result.decrypt(&client_key);
    assert_eq!(decrypted, 6u8);
}
```

# Dot Product

This document details the dot product operations supported by **TFHE-rs**.


| name          | symbol         | type   |
|---------------|----------------| ------ |
| Dot Product   | `dot_product`  | Binary |


Currently, the dot product supports the following case:
- One operand is a slice of `FheBool`
- The other operand is a slice of clear values (e.g., `u64`)
- Both slices must be of the same length

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

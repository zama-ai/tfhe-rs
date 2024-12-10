# Encrypt data

This document explains how to encrypt data.

To encrypt data, use the `encrypt` method from the `FheEncrypt` trait. This crate provides types that implement either `FheEncrypt` or `FheTryEncrypt` or both, to enable encryption.

Here is an example:

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, ConfigBuilder, FheUint8};

fn main() {
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    let clear_a = 27u8;
    let clear_b = 128u8;

    let a = FheUint8::encrypt(clear_a, &client_key);
    let b = FheUint8::encrypt(clear_b, &client_key);
}
```

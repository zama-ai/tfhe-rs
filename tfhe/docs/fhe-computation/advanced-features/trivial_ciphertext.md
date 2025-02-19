# Trivial ciphertexts

This document describes how to use trivial encryption in **TFHE-rs** to initialize server-side values.

Sometimes, the server side needs to initialize a value. For example, when computing the sum of a list of ciphertexts, you typically initialize the `sum` variable to `0`.

Instead of asking the client to send an actual encrypted zero, the server can use a trivial encryption. A trivial encryption creates a ciphertext that contains the desired value but isn't securely encrypted - essentially anyone, any key can decrypt it.

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};

let config = ConfigBuilder::default().build();
let (client_key, sks) = generate_keys(config);

set_server_key(sks);

let a = FheUint8::try_encrypt_trivial(234u8).unwrap();

let clear: u8 = a.decrypt(&client_key);
assert_eq!(clear, 234);
```

Note that when you want to do an operation that involves a ciphertext and a clear value (often called scalar operation), you should only use trivial encryption of the clear value if the scalar operations that you want to run are not supported.

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32};

let config = ConfigBuilder::default().build();
let (client_key, sks) = generate_keys(config);

set_server_key(sks);

// This is going to be faster
let a = FheUint32::try_encrypt(2097152u32, &client_key).unwrap();
let shift = 1u32;
let shifted = a << shift;
let clear: u32 = shifted.decrypt(&client_key);
assert_eq!(clear, 2097152 << 1);

// This is going to be slower
let a = FheUint32::try_encrypt(2097152u32, &client_key).unwrap();
let shift = FheUint32::try_encrypt_trivial(1u32).unwrap();
let shifted = a << shift;
let clear: u32 = shifted.decrypt(&client_key);
assert_eq!(clear, 2097152 << 1);
```

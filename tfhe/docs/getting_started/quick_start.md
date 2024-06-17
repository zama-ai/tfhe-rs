# Quick start

This document explains the basic steps of using the high-level API of **TFHE-rs.**

## Workflow explanation

These are the steps to use the **TFHE-rs** high-level API:

1. [Import the **TFHE-rs** prelude](quick\_start.md#imports)
2. Client-side: [configure and generate keys](../fundamentals/configure-and-generate-keys.md)
3. Client-side: [encrypt data](../fundamentals/encrypt-data.md)
4. Server-side: [set the server key](../fundamentals/set-the-server-key.md)
5. Server-side: [compute over encrypted data](../fundamentals/compute.md)
6. Client-side: [decrypt data](../fundamentals/decrypt-data.md)

This example demonstrates the basic workflow combining the client and server parts:

```rust
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint8};
use tfhe::prelude::*;

fn main() {
    let config = ConfigBuilder::default().build();

    // Client-side
    let (client_key, server_key) = generate_keys(config);

    let clear_a = 27u8;
    let clear_b = 128u8;

    let a = FheUint8::encrypt(clear_a, &client_key);
    let b = FheUint8::encrypt(clear_b, &client_key);

    //Server-side
    set_server_key(server_key);
    let result = a + b;

    //Client-side
    let decrypted_result: u8 = result.decrypt(&client_key);

    let clear_result = clear_a + clear_b;

    assert_eq!(decrypted_result, clear_result);
}
```

The default configuration for x86 Unix machines is as follows:

```toml
tfhe = { version = "0.6.3", features = ["integer", "x86_64-unix"]}
```

Refer to the [installation documentation](installation.md) for configuration options of different platforms.Learn more about homomorphic types features in the [configuration documentation.](../guides/rust\_configuration.md)

## Step1: Importing

**TFHE-rs** uses `traits` to implement consistent APIs and generic functions. To use `traits`, they must be in scope.

The `prelude` pattern provides a convenient way to globally import all important **TFHE-rs** traits at once. This approach saves time and avoids confusion.

```rust
use tfhe::prelude::*;
```

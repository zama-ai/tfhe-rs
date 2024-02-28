# Quick start

The basic steps for using the high-level API of TFHE-rs are:

1. [Importing the TFHE-rs prelude;](quick\_start.md#imports)
2. Client-side: [Configuring and creating keys;](../fundamentals/configure-and-create-keys.md)
3. Client-side: [Encrypting data;](../fundamentals/encrypt-data.md)
4. Server-side: [Setting the server key;](../fundamentals/set-the-server-key.md)
5. Server-side: [Computing over encrypted data;](../fundamentals/compute-and-decrypt.md)
6. Client-side: [Decrypting data.](../fundamentals/compute-and-decrypt.md)

Here is a full example (combining the client and server parts):

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

The default configuration for x86 Unix machines:

```toml
tfhe = { version = "0.5.2", features = ["integer", "x86_64-unix"]}
```

Configuration options for different platforms can be found [here](installation.md). Other rust and homomorphic types features can be found [here](../guides/rust\_configuration.md).

### Imports

`tfhe` uses `traits` to have a consistent API for creating FHE types and enable users to write generic functions. To be able to use associated functions and methods of a trait, the trait has to be in scope.

To make it easier, the `prelude` 'pattern' is used. All of the important `tfhe` traits are in a `prelude` module that you can **glob import**. With this, there is no need to remember or know the traits that you want to import.

```rust
use tfhe::prelude::*; 
```

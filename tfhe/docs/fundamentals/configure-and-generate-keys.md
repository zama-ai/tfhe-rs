# Configuration and key generation

This document explains how to initialize the configuration and generate keys.

The configuration specifies the selected data types and their custom crypto-parameters. You should only use custom parameters for advanced usage and/or testing.

To create a configuration, use the `ConfigBuilder` type. The following example shows the setup using 8-bit unsigned integers with default parameters. Additionally, ensure the `integers` feature is enabled, as indicated in the table on [this page](../guides/rust\_configuration.md#homomorphic-types).

The configuration is initialized by creating a builder with all types deactivated. Then, the integer types with default parameters are activated, for using `FheUint8` values.

```rust
use tfhe::{ConfigBuilder, generate_keys};

fn main() {
    let config = ConfigBuilder::default().build();


    let (client_key, server_key) = generate_keys(config);
}
```

The `generate_keys` command returns a client key and a server key:

* **Client\_key**: this key should remain private and never leave the client.
* **Server\_key**: this key can be public and sent to a server to enable FHE computations.

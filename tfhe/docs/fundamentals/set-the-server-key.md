# Set the server key

This document explains how to call the function `set_server_key`.

This function will **move** the server key to an internal state of the crate and manage the details for a simpler interface.

Here is an example:

```rust
use tfhe::{ConfigBuilder, generate_keys, set_server_key};

fn main() {
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);
}
```

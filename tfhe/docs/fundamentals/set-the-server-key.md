# Set the server key

The next step is to call `set_server_key`

This function will **move** the server key to an internal state of the crate and manage the details to give a simpler interface.

```rust
use tfhe::{ConfigBuilder, generate_keys, set_server_key};

fn main() {
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);
}
```

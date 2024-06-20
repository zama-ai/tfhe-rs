# Data versioning and backward compatibility

As of v0.6.4, the data types used in **tfhe-rs** are versioned, which means that it is now possible to store data at one point in time and load it in the future without worrying about **tfhe-rs** compatibility. This is done using the **tfhe-versionable** crate. This versioning scheme is compatible with all the [data formats](https://serde.rs/#data-formats) supported by serde.

## Saving and loading versioned data

To use this feature, you must wrap your types in their versioned equivalent before serialization. This is done with the `versionize` method.
Data serialized this way can be loaded with the `unversionize` function. Note that this can be done in a later version of **tfhe-rs**, and it will work even if the data types have evolved. The `unversionize` function takes care of any necessary data type upgrades.

```toml
# Cargo.toml

[dependencies]
# ...
tfhe = { version = "0.6.4", features = ["integer","x86_64-unix"]}
tfhe-versionable = "0.1.0"
bincode = "1.3.3"
```

```rust
// main.rs

use bincode;
use std::io::Cursor;
use tfhe::{ClientKey, ConfigBuilder};
use tfhe_versionable::{Unversionize, Versionize};

fn main() {
    let config = ConfigBuilder::default().build();

    let client_key = ClientKey::generate(config);

    // Versionize the key and store it
    let mut serialized_data = Vec::new();
    bincode::serialize_into(&mut serialized_data, &client_key.versionize()).unwrap();

    // Load the key. This can be done in the future with a more recent version of tfhe-rs
    let mut serialized_data = Cursor::new(serialized_data);
    let _client_key =
        ClientKey::unversionize(bincode::deserialize_from(&mut serialized_data).unwrap()).unwrap();
}
```

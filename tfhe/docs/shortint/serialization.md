# Serialization / Deserialization

As explained in the introduction, some types (`Serverkey`, `Ciphertext`) are meant to be shared
with the server that does the computations.

The easiest way to send these data to a server is to use the serialization and deserialization features.
tfhe::shortint uses the serde framework, serde's Serialize and Deserialize are implemented on 
tfhe::shortint's
types.

To be able to serialize our data, we need to pick a [data format], for our use case,
[bincode] is a good choice, mainly because it is binary format.


```toml
# Cargo.toml

[dependencies]
# ...
bincode = "1.3.3"
```


```rust
// main.rs

use bincode;
use std::io::Cursor;
use tfhe::shortint::prelude::*;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (client_key, server_key) = gen_keys(Parameters::default());

    let msg1 = 1;
    let msg2 = 0;

    let ct_1 = client_key.encrypt(msg1);
    let ct_2 = client_key.encrypt(msg2);

    let mut serialized_data = Vec::new();
    bincode::serialize_into(&mut serialized_data, &server_key)?;
    bincode::serialize_into(&mut serialized_data, &ct_1)?;
    bincode::serialize_into(&mut serialized_data, &ct_2)?;

    // Simulate sending serialized data to a server and getting
    // back the serialized result
    let serialized_result = server_function(&serialized_data)?;
    let result: Ciphertext = bincode::deserialize(&serialized_result)?;

    let output = client_key.decrypt(&result);
    assert_eq!(output, msg1 + msg2);
    Ok(())
}


fn server_function(serialized_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut serialized_data = Cursor::new(serialized_data);
    let server_key: ServerKey = bincode::deserialize_from(&mut serialized_data)?;
    let ct_1: Ciphertext = bincode::deserialize_from(&mut serialized_data)?;
    let ct_2: Ciphertext = bincode::deserialize_from(&mut serialized_data)?;

    let result = server_key.unchecked_add(&ct_1, &ct_2);

    let serialized_result = bincode::serialize(&result)?;

    Ok(serialized_result)
}
```

[serde]: https://crates.io/crates/serde
[data format]: https://serde.rs/#data-formats
[bincode]: https://crates.io/crates/bincode 

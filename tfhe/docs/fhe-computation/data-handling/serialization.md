# Serialization/deserialization

This document explains the `serialization` and `deserialization` features that are useful to send data to a server to perform the computations.

## Safe serialization/deserialization

When dealing with sensitive types, it's important to implement safe serialization and safe deserialization functions to prevent runtime errors and enhance security. **TFHE-rs** provide easy to use functions for this purpose, such as `safe_serialize`, `safe_deserialize` and `safe_deserialize_conformant`.

Here is a basic example on how to use it:

```rust
// main.rs

use tfhe::safe_serialization::{safe_deserialize_conformant, safe_serialize};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use tfhe::ServerKey;
use tfhe::{generate_keys, ConfigBuilder};

fn main() {
    let params_1 = PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    let config = ConfigBuilder::with_custom_parameters(params_1).build();

    let (client_key, server_key) = generate_keys(config);

    let mut buffer = vec![];

    // The last argument is the max allowed size for the serialized buffer
    safe_serialize(&server_key, &mut buffer, 1 << 30).unwrap();

    let _server_key_deser: ServerKey =
        safe_deserialize_conformant(buffer.as_slice(), 1 << 30, &config.into()).unwrap();
}
```

The safe deserialization must take the output of a safe-serialization as input. During the process, the following validation occurs:

* **Type match**: deserializing `type A` from a serialized `type B` raises an error indicating "On deserialization, expected type A, got type B".
* **Version compatibility**: data serialized in previous versions of **TFHE-rs** are automatically upgraded to the latest version using the [data versioning](data-versioning.md) feature.
* **Parameter compatibility**: deserializing an object of `type A` with one set of crypto parameters from an object of `type A` with another set of crypto parameters raises an error indicating "Deserialized object of type A not conformant with given parameter set"
  * If both parameter sets have the same LWE dimension for ciphertexts, a ciphertext from param 1 may not fail this deserialization check with param 2.
  * This check can't distinguish ciphertexts/server keys from independent client keys with the same parameters.
  * This check is meant to prevent runtime errors in server homomorphic operations by checking that server keys and ciphertexts are compatible with the same parameter set.
  * You can use the standalone `is_conformant` method to check parameter compatibility. Besides, the `safe_deserialize_conformant` function includes the parameter compatibility check, and the `safe_deserialize` function does not include the compatibility check.
* **Size limit**: both serialization and deserialization processes expect a size limit (measured in bytes) for the serialized data:
  * On serialization, an error is raised if the serialized output exceeds the specific limit.
  * On deserialization, an error is raised if the serialized input exceeds the specific limit.

This feature aims to gracefully return an error in case of an attacker trying to cause an out-of-memory error on deserialization.

Here is a more complete example:

```rust
// main.rs

use tfhe::conformance::ParameterSetConformant;
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_serialize, safe_deserialize_conformant};
use tfhe::shortint::parameters::{
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128};
use tfhe::conformance::ListSizeConstraint;
use tfhe::{
    generate_keys, FheUint8, CompactCiphertextList, FheUint8ConformanceParams,
    CompactPublicKey, ConfigBuilder, CompactCiphertextListConformanceParams
};

fn main() {
    let params_1 = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let params_2 = PARAM_MESSAGE_3_CARRY_3_KS_PBS_GAUSSIAN_2M128;

    assert_ne!(params_1, params_2);

    let config = ConfigBuilder::with_custom_parameters(params_1).build();

    let (client_key, server_key) = generate_keys(config);

    let conformance_params_1 = FheUint8ConformanceParams::from(params_1);
    let conformance_params_2 = FheUint8ConformanceParams::from(params_2);

    let public_key = CompactPublicKey::new(&client_key);

    let msg = 27u8;

    let ct = FheUint8::try_encrypt(msg, &client_key).unwrap();

    assert!(ct.is_conformant(&conformance_params_1));
    assert!(!ct.is_conformant(&conformance_params_2));

    let mut buffer = vec![];

    safe_serialize(&ct, &mut buffer, 1 << 20).unwrap();

    assert!(safe_deserialize_conformant::<FheUint8>(buffer.as_slice(), 1 << 20, &conformance_params_2)
        .is_err());

    let ct2: FheUint8 = safe_deserialize_conformant(buffer.as_slice(), 1 << 20, &conformance_params_1)
        .unwrap();

    let dec: u8 = ct2.decrypt(&client_key);
    assert_eq!(msg, dec);


    // Example with a compact list:
    let msgs = [27, 188u8];
    let mut builder = CompactCiphertextList::builder(&public_key);
    builder.extend(msgs.iter().copied());
    let compact_list = builder.build_packed();

    let mut buffer = vec![];
    safe_serialize(&compact_list, &mut buffer, 1 << 20).unwrap();

    let conformance_params =
        CompactCiphertextListConformanceParams::from_parameters_and_size_constraint(
           params_1.try_into().unwrap(),
           ListSizeConstraint::exact_size(2));
    safe_deserialize_conformant::<CompactCiphertextList>(buffer.as_slice(), 1 << 20, &conformance_params)
        .unwrap();
}
```

The safe serialization and deserialization use `bincode` internally.

To selectively disable some of the features of the safe serialization, you can use `SerializationConfig`/`DeserializationConfig` builders. For example, it is possible to disable the data versioning:

```rust
// main.rs

use tfhe::safe_serialization::{safe_deserialize_conformant, SerializationConfig};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use tfhe::ServerKey;
use tfhe::{generate_keys, ConfigBuilder};

fn main() {
    let params_1 = PARAM_MESSAGE_2_CARRY_2_KS_PBS;

    let config = ConfigBuilder::with_custom_parameters(params_1).build();

    let (client_key, server_key) = generate_keys(config);

    let mut buffer = vec![];

    SerializationConfig::new(1 << 30).disable_versioning().serialize_into(&server_key, &mut buffer).unwrap();

    // You will still be able to load this item with `safe_deserialize_conformant`, but only using the current version of TFHE-rs
    let _server_key_deser: ServerKey =
        safe_deserialize_conformant(buffer.as_slice(), 1 << 30, &config.into()).unwrap();
}
```

## Serialization/deserialization using serde

**TFHE-rs** uses the [Serde](https://crates.io/crates/serde) framework and implements Serde's `Serialize` and `Deserialize` traits.

This allows you to serialize into any [data format](https://serde.rs/#data-formats) supported by serde. However, this is a more bare bone approach as none of the checks described in the previous section will be performed for you.

In the following example, we use [bincode](https://crates.io/crates/bincode) for its binary format:

```toml
# Cargo.toml

[dependencies]
# ...
tfhe = { version = "~1.5.3", features = ["integer"] }
bincode = "1.3.3"
```

```rust
// main.rs

use std::io::Cursor;
use tfhe::{ConfigBuilder, ServerKey, generate_keys, set_server_key, FheUint8};
use tfhe::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>>{
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    let msg1 = 1;
    let msg2 = 0;

    let value_1 = FheUint8::encrypt(msg1, &client_key);
    let value_2 = FheUint8::encrypt(msg2, &client_key);

    // Prepare to send data to the server
    // The ClientKey is _not_ sent
    let mut serialized_data = Vec::new();
    bincode::serialize_into(&mut serialized_data, &server_key)?;
    bincode::serialize_into(&mut serialized_data, &value_1)?;
    bincode::serialize_into(&mut serialized_data, &value_2)?;

    // Simulate sending serialized data to a server and getting
    // back the serialized result
    let serialized_result = server_function(&serialized_data)?;
    let result: FheUint8 = bincode::deserialize(&serialized_result)?;

    let output: u8 = result.decrypt(&client_key);
    assert_eq!(output, msg1 + msg2);
    Ok(())
}


fn server_function(serialized_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut serialized_data = Cursor::new(serialized_data);
    let server_key: ServerKey = bincode::deserialize_from(&mut serialized_data)?;
    let ct_1: FheUint8 = bincode::deserialize_from(&mut serialized_data)?;
    let ct_2: FheUint8 = bincode::deserialize_from(&mut serialized_data)?;

    set_server_key(server_key);

    let result = ct_1 + ct_2;

    let serialized_result = bincode::serialize(&result)?;

    Ok(serialized_result)
}
```

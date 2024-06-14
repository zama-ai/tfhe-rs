# Serialization/deserialization

This document explains the `serialization` and `deserialization` features that are useful to send data to a server to perform the computations.

## Serialization/deserialization

**TFHE-rs** uses the [Serde](https://crates.io/crates/serde) framework and implements Serde's `Serialize` and `Deserialize` traits.

To serialize the data, you need to choose a [data format](https://serde.rs/#data-formats). In the following example, we use [bincode](https://crates.io/crates/bincode) for its binary format.

Here is a full example:

```toml
# Cargo.toml

[dependencies]
# ...
tfhe = { version = "0.7.0", features = ["integer","x86_64-unix"]}
bincode = "1.3.3"
```

```rust
// main.rs

use bincode;
use std::io::Cursor;
use tfhe::{ConfigBuilder, ServerKey, generate_keys, set_server_key, FheUint8};
use tfhe::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>>{
    let config = ConfigBuilder::default().build();

    let ( client_key, server_key) = generate_keys(config);

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

## Safe serialization/deserialization

When dealing with sensitive types, it's important to implement safe serialization and safe deserialization functions to prevent runtime errors and enhance security. The safe serialization and deserialization use `bincode` internally.

The safe deserialization must take the output of a safe-serialization as input. During the process, the following validation occurs:

* **Type match**: deserializing `type A` from a serialized `type B` raises an error indicating "On deserialization, expected type A, got type B".
* **Version compatibility**: deserializing `type A` of a newer version (for example, version 0.2) from a serialized `type A` of an older version (for example, version 0.1) raises an error indicating "On deserialization, expected serialization version 0.2, got version 0.1".
* **Parameter compatibility**: deserializing an object of `type A` with one set of crypto parameters from an object of `type A` with another set of crypto parameters raises an error indicating "Deserialized object of type A not conformant with given parameter set"
  * If both parameter sets have the same LWE dimension for ciphertexts, a ciphertext from param 1 may not fail this deserialization check with param 2.
  * This check can't distinguish ciphertexts/server keys from independent client keys with the same parameters.
  * This check is meant to prevent runtime errors in server homomorphic operations by checking that server keys and ciphertexts are compatible with the same parameter set.
  * You can use the standalone `is_conformant` method to check parameter compatibility. Besides, the `safe_deserialize_conformant` function includes the parameter compatibility check, and the `safe_deserialize` function does not include the compatibility check.
* **Size limit**: both serialization and deserialization processes expect a size limit (measured in bytes) for the serialized data:
  * On serialization, an error is raised if the serialized output exceeds the specific limit.
  * On deserialization, an error is raised if the serialized input exceeds the specific limit.

This feature aims to gracefully return an error in case of an attacker trying to cause an out-of-memory error on deserialization.

Here is an example:

```rust
// main.rs

use tfhe::conformance::ParameterSetConformant;
use tfhe::integer::parameters::RadixCiphertextConformanceParams;
use tfhe::prelude::*;
use tfhe::safe_deserialization::{safe_deserialize_conformant, safe_serialize};
use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_2_CARRY_2_PBS_KS};
use tfhe::conformance::ListSizeConstraint;
use tfhe::{
    generate_keys, FheUint8, CompactCiphertextList, FheUint8ConformanceParams,
    CompactPublicKey, ConfigBuilder, CompactCiphertextListConformanceParams
};

fn main() {
    let config = ConfigBuilder::default().build();

    let params_1 = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    let params_2 = PARAM_MESSAGE_2_CARRY_2_PBS_KS;
    
    let (client_key, server_key) = generate_keys(
        ConfigBuilder::with_custom_parameters(params_1, None, None).build()
    );
    
    let conformance_params_1 = FheUint8ConformanceParams::from(params_1);
    let conformance_params_2 = FheUint8ConformanceParams::from(params_2);
    
    let public_key = CompactPublicKey::new(&client_key);

    let msg = 27u8;

    let ct = FheUint8::try_encrypt(msg, &client_key).unwrap();
    
    assert!(ct.is_conformant(&conformance_params_1));
    assert!(!ct.is_conformant(&conformance_params_2));

    let mut buffer = vec![];

    safe_serialize(&ct, &mut buffer, 1 << 40).unwrap();
    
    assert!(safe_deserialize_conformant::<FheUint8>(
        buffer.as_slice(),
        1 << 20,
        &conformance_params_2
    ).is_err());

    let ct2 = safe_deserialize_conformant::<FheUint8>(
        buffer.as_slice(),
        1 << 20,
        &conformance_params_1
    ).unwrap();

    let dec: u8 = ct2.decrypt(&client_key);
    assert_eq!(msg, dec);
    
    
    // Example with a compact list:
    let msgs = [27, 188u8];
    let mut builder = CompactCiphertextList::builder(&public_key);
    builder.extend(msgs.iter().copied());
    let compact_list = builder.build();

    let mut buffer = vec![];
    safe_serialize(&compact_list, &mut buffer, 1 << 40).unwrap();
    
    let conformance_params = CompactCiphertextListConformanceParams {
        shortint_params: params_1.to_shortint_conformance_param(),
        num_elements_constraint: ListSizeConstraint::exact_size(2),
    };
    assert!(safe_deserialize_conformant::<CompactCiphertextList>(
        buffer.as_slice(),
        1 << 20,
        &conformance_params
    ).is_ok());
}
```

# Serialization/Deserialization

As explained in the Introduction, most types are meant to be shared with the server that performs the computations.

The easiest way to send these data to a server is to use the `serialization` and `deserialization` features. `tfhe` uses the [serde](https://crates.io/crates/serde) framework. Serde's `Serialize` and `Deserialize` functions are implemented on TFHE's types.

To serialize our data, a [data format](https://serde.rs/#data-formats) should be picked. Here, [bincode](https://crates.io/crates/bincode) is a good choice, mainly because it is a binary format.

```toml
# Cargo.toml

[dependencies]
# ...
tfhe = { version = "0.6.0", features = ["integer","x86_64-unix"]}
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


# Safe Serialization/Deserialization

For some types, safe serialization and deserialization functions are available.
Bincode is used internally.

Safe-deserialization must take as input the output of a safe-serialization.
On this condition, validation of the following is done:
- type: trying to deserialize `type A` from a serialized `type B` raises an error along the lines of *On deserialization, expected type A, got type B* instead of a generic deserialization error (or less likely a meaningless result of `type A`)
- version: trying to deserialize `type A` (version 0.2) from a serialized `type A` (incompatible version 0.1) raises an error along the lines of *On deserialization, expected serialization version 0.2, got version 0.1* instead of a generic deserialization error (or less likely a meaningless result of `type A` (version 0.2))
- parameter compatibility: trying to deserialize into an object of `type A` with some crypto parameters from a an object of `type A` with other crypto parameters raises an error along the lines of *Deserialized object of type A not conformant with given parameter set*.
If both parameters sets 1 and 2 have the same lwe dimension for ciphertexts, a ciphertext from param 1 may not fail this deserialization check with param 2 even if doing this deserialization may not make sense.
Also, this check can't distinguish ciphertexts/server keys from independant client keys with the same parameters (which makes no sense combining to do homomorphic operations).
This check is meant to prevent runtime errors in server homomorphic operations by checking that server keys and ciphertexts are compatible with the same parameter set.

Moreover, a size limit (in number of bytes) for the serialized data is expected on both serialization and deserialization.
On serialization, an error is raised if the serialized output would be bigger than the given limit.
On deserialization, an error is raised if the serialized input is bigger than the given limit.
It is meant to gracefully return an error in case of an attacker trying to cause an out of memory error on deserialization. 

A standalone `is_conformant` method is also available on those types to do a parameter compatibility check.

Parameter compatibility check is done by `safe_deserialize_conformant` function but a `safe_deserialize` function without this check is also available.

```rust
// main.rs

use tfhe::conformance::ParameterSetConformant;
use tfhe::integer::parameters::RadixCiphertextConformanceParams;
use tfhe::prelude::*;
use tfhe::safe_deserialization::{safe_deserialize_conformant, safe_serialize};
use tfhe::shortint::parameters::{PARAM_MESSAGE_2_CARRY_2_KS_PBS, PARAM_MESSAGE_3_CARRY_3_KS_PBS};
use tfhe::{generate_keys, CompactFheUint8, CompactPublicKey, ConfigBuilder};

fn main() {
    let config = ConfigBuilder::default().build();

    let (client_key, _server_key) = generate_keys(config);

    let public_key = CompactPublicKey::new(&client_key);

    let msg = 27u8;

    let num_blocks_per_integer = 4;

    let ct = CompactFheUint8::try_encrypt(msg, &public_key).unwrap();

    assert!(
        ct.is_conformant(&RadixCiphertextConformanceParams::from_pbs_parameters(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            num_blocks_per_integer
        ))
    );

    assert!(
        !ct.is_conformant(&RadixCiphertextConformanceParams::from_pbs_parameters(
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            num_blocks_per_integer
        ))
    );

    let mut buffer = vec![];

    safe_serialize(&ct, &mut buffer, 1 << 40).unwrap();

    assert!(safe_deserialize_conformant::<CompactFheUint8>(
        buffer.as_slice(),
        1 << 20,
        &RadixCiphertextConformanceParams::from_pbs_parameters(
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            num_blocks_per_integer
        ),
    )
    .is_err());

    let ct2 = safe_deserialize_conformant::<CompactFheUint8>(
        buffer.as_slice(),
        1 << 20,
        &RadixCiphertextConformanceParams::from_pbs_parameters(
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            num_blocks_per_integer,
        ),
    )
    .unwrap();

    let dec: u8 = ct2.expand().decrypt(&client_key);
    assert_eq!(msg, dec);
}
```

# Public key encryption

This document explains public key encryption and provides instructions for using it.

Public key encryption refers to the cryptographic paradigm where the encryption key can be publicly distributed, whereas the decryption key remains secret to the owner. This differs from the usual case where the same secret key is used to encrypt and decrypt the data. In **TFHE-rs**, public key encryption uses a **compact public key**, based on the paper [TFHE Public-Key Encryption Revisited](https://eprint.iacr.org/2023/603).

Public keys can also be [compressed](../data-handling/compress.md) to reduce size.

## Compact public key

This example shows how to use compact public keys.

For more information on using compact public keys to encrypt data and generate a zero-knowledge proof of correct encryption at the same time, see [the guide on ZK proofs](zk-pok.md).

```rust
use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, CompactCiphertextList, CompactPublicKey, ConfigBuilder,
    FheUint8,
};


fn main() {
     let config = ConfigBuilder::default()
        .use_custom_parameters(
            tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
        )
        .build();
    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key);

    let public_key = CompactPublicKey::new(&client_key);
    let compact_list = CompactCiphertextList::builder(&public_key)
        .push(255u8)
        .build();
    let expanded = compact_list.expand().unwrap();
    let a: FheUint8 = expanded.get(0).unwrap().unwrap();

    let clear: u8 = a.decrypt(&client_key);
    assert_eq!(clear, 255u8);
}
```

# Public key encryption

This document explains public key encryption and provides instructions for 2 methods.

Public key encryption refers to the cryptographic paradigm where the encryption key can be publicly distributed, whereas the decryption key remains secret to the owner. This differs from the usual case where the same secret key is used to encrypt and decrypt the data. In **TFHE-rs**, there are two methods for public key encryptions:

* **Classical public key**: the first method involves the public key containing many encryptions of zero, as detailed in [Guide to Fully Homomorphic Encryption over the \[Discretized\] Torus, Appendix A.](https://eprint.iacr.org/2021/1402)
* **Compact public key**: the second method is based on the paper [TFHE Public-Key Encryption Revisited](https://eprint.iacr.org/2023/603), allowing for significantly smaller key sizes compared to the first method.

Public keys can also be [compressed](../fundamentals/compress.md) to reduce size.

## Classical public key

This example shows how to use classical public keys.

```rust
use tfhe::prelude::*;
use tfhe::{ConfigBuilder, generate_keys, FheUint8, PublicKey};

fn main() {
    let config = ConfigBuilder::default().build();
    let (client_key, _) = generate_keys(config);

    let public_key = PublicKey::new(&client_key);

    let a = FheUint8::try_encrypt(255u8, &public_key).unwrap();
    let clear: u8 = a.decrypt(&client_key);
    assert_eq!(clear, 255u8);
}
```

## Compact public key

This example shows how to use compact public keys. The main difference is in the `ConfigBuilder` where the parameter set has been changed.

For more information on using compact public keys to encrypt data and generate a zero-knowledge proof of correct encryption at the same time, see [the guide on ZK proofs](zk-pok.md).

```rust
use tfhe::prelude::*;
use tfhe::{
    generate_keys, CompactCiphertextList, CompactPublicKey, ConfigBuilder, FheUint8,
};


fn main() {
     let config = ConfigBuilder::default()
        .use_custom_parameters(
            tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M64,
        )
        .build();
    let (client_key, _) = generate_keys(config);

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

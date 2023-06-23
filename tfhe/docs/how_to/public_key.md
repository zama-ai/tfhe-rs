
# Public Key Encryption
Public key encryption refers to the cryptographic paradigm where the encryption key can be publicly distributed, whereas the decryption key remains secret to the owner. This differs from usual case where the same secret key is used to encrypt and decrypt the data. In TFHE-rs, there exists two methods for public key encryptions. First, the usual one, where the public key contains ma y encryption of zeroes. More details can be found in [Guide to Fully Homomorphic Encryption over the [Discretized] Torus, Appendix A.](https://eprint.iacr.org/2021/1402). The second method is based on the paper entitled [TFHE Public-Key Encryption Revisited](https://eprint.iacr.org/2023/603). The main advantage of the latter method in comparison with the former lies into the key sizes, which are drastically reduced.

Note that public keys can be [compressed](./compress.md)

## classical public key 
This example shows how to use public keys.

```rust
use tfhe::prelude::*;
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint8, PublicKey};

fn main() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();
    let (client_key, _) = generate_keys(config);

    let public_key = PublicKey::new(&client_key);

    let a = FheUint8::try_encrypt(255u8, &public_key).unwrap();
    let clear: u8 = a.decrypt(&client_key);
    assert_eq!(clear, 255u8);
}
```

## compact public key
This example shows how to use compact public keys. The main difference is in the ConfigBuilder, where the parameter set has been changed.


```rust
use tfhe::prelude::*;
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint8, CompactPublicKey};

fn main() {
     let config = ConfigBuilder::all_disabled()
        .enable_custom_integers(
            tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS,
            None,
        )
        .build();
    let (client_key, _) = generate_keys(config);

    let public_key = CompactPublicKey::new(&client_key);

    let a = FheUint8::try_encrypt(255u8, &public_key).unwrap();
    let clear: u8 = a.decrypt(&client_key);
    assert_eq!(clear, 255u8);
}
```


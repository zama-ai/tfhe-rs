# Zero-knowledge proofs

This document explains how to implement the zero-knowledge proofs function for compact public key encryption to verify the encryption process without revealing the encrypted information.

**TFHE-rs** can generate zero-knowledge proofs to verify that the compact public key encryption process is correct. In other words, **TFHE-rs** generates the proof without revealing any information other than the already known range of the encrypted message. This technique is derived from [Libert’s work](https://eprint.iacr.org/2023/800).

{% hint style="info" %}
You can enable this feature using the flag: `--features=zk-pok-experimental` when building **TFHE-rs**.
{% endhint %}

Using this feature is straightforward: during encryption, the client generates the proof, and the server validates it before conducting any homomorphic computations. The following example demonstrates how a client can encrypt and prove a ciphertext, and how a server can verify the ciphertext and compute it:

```rust
use rand::prelude::*;
use tfhe::prelude::FheDecrypt;
use tfhe::set_server_key;
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad};

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    let params =
        tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    let config = tfhe::ConfigBuilder::with_custom_parameters(params, None);

    let client_key = tfhe::ClientKey::generate(config.clone());
    // This is done in an offline phase and the CRS is shared to all clients and the server
    let crs = CompactPkeCrs::from_config(config.into(), 64).unwrap();
    let public_zk_params = crs.public_params();
    let server_key = tfhe::ServerKey::new(&client_key);
    let public_key = tfhe::CompactPublicKey::try_new(&client_key).unwrap();

    let clear_a = rng.gen::<u64>();
    let clear_b = rng.gen::<u64>();
    
    let proven_compact_list = tfhe::ProvenCompactCiphertextList::builder(&public_key)
        .push(clear_a)
        .push(clear_b)
        .build_with_proof(public_zk_params, ZkComputeLoad::Proof)?;

    // Server side
    let result = {
        set_server_key(server_key);

        // Verify the ciphertexts
        let mut expander = proven_compact_list.verify_and_expand(&public_zk_params, &public_key)?;
        let a: tfhe::FheUint64 = expander.get(0).unwrap()?;
        let b: tfhe::FheUint64 = expander.get(1).unwrap()?;

        a + b
    };

    // Back on the client side
    let a_plus_b: u64 = result.decrypt(&client_key);
    assert_eq!(a_plus_b, clear_a.wrapping_add(clear_b));

    Ok(())
}
```

In terms of performance one can expect the following numbers:

* Encrypting and proving a `CompactFheUint64` takes **6.9 s** on a `Dell XPS 15 9500` (simulating a client machine).
* Verification takes **123 ms** on an `hpc7a.96xlarge` AWS instances.

Performance can be improved by setting `lto="fat"` in `Cargo.toml`
```toml
[profile.release]
lto = "fat"
```
and by building the code for the native CPU architecture and in release mode, e.g. by calling `RUSTFLAGS="-C target-cpu=native" cargo run --release`.

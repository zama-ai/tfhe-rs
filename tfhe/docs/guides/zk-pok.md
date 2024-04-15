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
use tfhe::shortint::parameters::DynamicDistribution;
use tfhe::set_server_key;
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad};

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    let max_num_message = 1;

    let mut params =
        tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M40;

    let client_key = tfhe::ClientKey::generate(tfhe::ConfigBuilder::with_custom_parameters(params, None));
    // This is done in an offline phase and the CRS is shared to all clients and the server
    let crs = CompactPkeCrs::from_shortint_params(params, max_num_message).unwrap();
    let public_zk_params = crs.public_params();
    let server_key = tfhe::ServerKey::new(&client_key);
    let public_key = tfhe::CompactPublicKey::try_new(&client_key).unwrap();

    let clear_a = rng.gen::<u64>();
    let clear_b = rng.gen::<u64>();

    let a = tfhe::ProvenCompactFheUint64::try_encrypt(
        clear_a,
        public_zk_params,
        &public_key,
        ZkComputeLoad::Proof,
    )?;
    let b = tfhe::ProvenCompactFheUint64::try_encrypt(
        clear_b,
        public_zk_params,
        &public_key,
        ZkComputeLoad::Proof,
    )?;

    // Server side
    let result = {
        set_server_key(server_key);

        // Verify the ciphertexts
        let a = a.verify_and_expand(&public_zk_params, &public_key)?;
        let b = b.verify_and_expand(&public_zk_params, &public_key)?;

        a + b
    };

    // Back on the client side
    let a_plus_b: u64 = result.decrypt(&client_key);
    assert_eq!(a_plus_b, clear_a.wrapping_add(clear_b));

    Ok(())
}
```

In terms of performance:

* Encrypting and proving a `CompactFheUint64` takes **6.9 s** on a `Dell XPS 15 9500` (simulating a client machine).
* Verification takes **123 ms** on an `hpc7a.96xlarge` AWS instances.

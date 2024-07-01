# Zero-knowledge proofs

This document explains how to implement the zero-knowledge proofs function for compact public key encryption to verify the encryption process without revealing the encrypted information.

**TFHE-rs** can generate zero-knowledge proofs to verify that the compact public key encryption process is correct. In other words, **TFHE-rs** generates the proof without revealing any information other than the already known range of the encrypted message. This technique is derived from [Libert’s work](https://eprint.iacr.org/2023/800).

{% hint style="info" %}
You can enable this feature using the flag: `--features=zk-pok` when building **TFHE-rs**.
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
        .build_with_proof_packed(public_zk_params, ZkComputeLoad::Proof)?;

    // Server side
    let result = {
        set_server_key(server_key);

        // Verify the ciphertexts
        let mut expander = proven_compact_list.verify_and_expand(public_zk_params, &public_key)?;
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

Performance can be improved by setting `lto="fat"` in `Cargo.toml`
```toml
[profile.release]
lto = "fat"
```
and by building the code for the native CPU architecture and in release mode, e.g. by calling `RUSTFLAGS="-C target-cpu=native" cargo run --release`.

{% hint style="info" %}
You can choose a more costly proof with `ZkComputeLoad::Proof`, which has a faster verification time.  Alternatively, you can select `ZkComputeLoad::Verify` for a faster proof and slower verification.
{% endhint %}

## Using dedicated Compact Public Key parameters

### A first example
You can use dedicated parameters for the compact public key encryption to reduce the size of encrypted data and speed up the zero-knowledge proof computation.

This works essentially in the same way as before. Additionally, you need to indicate the dedicated parameters to use:

```rust
use rand::prelude::*;
use tfhe::prelude::FheDecrypt;
use tfhe::set_server_key;
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad};

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    let params = tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    // Indicate which parameters to use for the Compact Public Key encryption
    let cpk_params = tfhe::shortint::parameters::compact_public_key_only::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    // And parameters allowing to keyswitch/cast to the computation parameters.
    let casting_params = tfhe::shortint::parameters::key_switching::PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    // Enable the dedicated parameters on the config
    let config = tfhe::ConfigBuilder::with_custom_parameters(params, None)
        .use_dedicated_compact_public_key_parameters((cpk_params, casting_params));

    // Then use TFHE-rs as usual
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
        .build_with_proof_packed(public_zk_params, ZkComputeLoad::Verify)?;

    // Server side
    let result = {
        set_server_key(server_key);

        // Verify the ciphertexts
        let mut expander = proven_compact_list.verify_and_expand(public_zk_params, &public_key)?;
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

### Benchmarks
Benchmarks for the proofs have been run on a `m6i.4xlarge` with 16 cores to simulate an usual client configuration.  The verification are done on a `hpc7a.96xlarge` AWS instances to mimic a powerful server. 

Timings in the case where the workload is mainly on the prover, i.e., with the  `ZkComputeLoad::Proof` option.

| Inputs       | Proving | Verifying |
|--------------|---------|-----------|
| 1xFheUint64  | 2.79s   | 197ms     |
| 10xFheUint64 | 3.68s   | 251ms     |
 

Timings in the case where the workload is mainly on the verifier, i.e., with the  `ZkComputeLoad::Verify` option.

| Inputs       | Proving | Verifying |
|--------------|---------|-----------|
| 1xFheUint64  | 730ms   | 522ms     |
| 10xFheUint64 | 1.08s   | 682ms     |

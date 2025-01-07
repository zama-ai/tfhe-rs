# Zero-knowledge proofs

This document explains how to implement the zero-knowledge proofs function for compact public key encryption to verify the encryption process without revealing the encrypted information.

**TFHE-rs** can generate zero-knowledge proofs to verify that the compact public key encryption process is correct. In other words, **TFHE-rs** generates the proof without revealing any information other than the already known range of the encrypted message. This technique is derived from [Libert’s work](https://eprint.iacr.org/2023/800).

{% hint style="info" %}
You can enable this feature using the flag: `--features=zk-pok` when building **TFHE-rs**.
{% endhint %}

To use this feature, you must first generate a **CRS** (Common Reference String). The CRS is a piece of cryptographic data that is necessary to ensure the security of zero-knowledge proofs. The CRS should be generated in advance and shared between all the clients and the server. A CRS can be reused for multiple encryptions with the same parameters.

Once the CRS is generated, using zero-knowledge proofs is straightforward: during encryption, the client generates the proof, and the server validates it before performing any homomorphic computations.

Note that you need to use dedicated parameters for the compact public key encryption. This helps to reduce the size of encrypted data and speed up the zero-knowledge proof computation.

The following example shows how a client can encrypt and prove a ciphertext, and how a server can verify and compute the ciphertext:

```rust
use rand::prelude::*;
use tfhe::prelude::*;
use tfhe::set_server_key;
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad};

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    let params = tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    // Indicate which parameters to use for the Compact Public Key encryption
    let cpk_params = tfhe::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    // And parameters allowing to keyswitch/cast to the computation parameters.
    let casting_params = tfhe::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    // Enable the dedicated parameters on the config
    let config = tfhe::ConfigBuilder::with_custom_parameters(params)
        .use_dedicated_compact_public_key_parameters((cpk_params, casting_params)).build();

    // The CRS should be generated in an offline phase then shared to all clients and the server
    let crs = CompactPkeCrs::from_config(config, 64).unwrap();

    // Then use TFHE-rs as usual
    let client_key = tfhe::ClientKey::generate(config);
    let server_key = tfhe::ServerKey::new(&client_key);
    let public_key = tfhe::CompactPublicKey::try_new(&client_key).unwrap();
    // This can be left empty, but if provided allows to tie the proof to arbitrary data
    let metadata = [b'T', b'F', b'H', b'E', b'-', b'r', b's'];

    let clear_a = rng.gen::<u64>();
    let clear_b = rng.gen::<u64>();

    let proven_compact_list = tfhe::ProvenCompactCiphertextList::builder(&public_key)
        .push(clear_a)
        .push(clear_b)
        .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Verify)?;

    // Server side
    let result = {
        set_server_key(server_key);

        // Verify the ciphertexts
        let expander =
            proven_compact_list.verify_and_expand(&crs, &public_key, &metadata)?;
        let a: tfhe::FheUint64 = expander.get(0)?.unwrap();
        let b: tfhe::FheUint64 = expander.get(1)?.unwrap();

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

## Scheme version
The ZK scheme used to generate and verify proofs is available in two versions:

- ZKV1: This version is close to the original paper from [Libert](https://eprint.iacr.org/2023/800).
- ZKV2: Differing from the paper, this version provides better performance for provers and verifiers.

**TFHE-rs** selects automatically the scheme to use based on the encryption parameters during the CRS generation. With default parameters, ZKV2 is selected.

The following example shows how to generate a CRS and proofs for ZKV1. Compared to the previous example, only the parameters are changed:
```rust
use rand::prelude::*;
use tfhe::prelude::*;
use tfhe::set_server_key;
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad};

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();

    let params = tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    // Indicate which parameters to use for the Compact Public Key encryption
    let cpk_params = tfhe::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64_ZKV1;
    // And parameters allowing to keyswitch/cast to the computation parameters.
    let casting_params = tfhe::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64_ZKV1;
    // Enable the dedicated parameters on the config
    let config = tfhe::ConfigBuilder::with_custom_parameters(params)
        .use_dedicated_compact_public_key_parameters((cpk_params, casting_params)).build();

    // The CRS should be generated in an offline phase then shared to all clients and the server
    let crs = CompactPkeCrs::from_config(config, 64).unwrap();

    // Then use TFHE-rs as usual
    let client_key = tfhe::ClientKey::generate(config);
    let server_key = tfhe::ServerKey::new(&client_key);
    let public_key = tfhe::CompactPublicKey::try_new(&client_key).unwrap();
    // This can be left empty, but if provided allows to tie the proof to arbitrary data
    let metadata = [b'T', b'F', b'H', b'E', b'-', b'r', b's'];

    let clear_a = rng.gen::<u64>();
    let clear_b = rng.gen::<u64>();

    let proven_compact_list = tfhe::ProvenCompactCiphertextList::builder(&public_key)
        .push(clear_a)
        .push(clear_b)
        .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Verify)?;

    // Server side
    let result = {
        set_server_key(server_key);

        // Verify the ciphertexts
        let expander =
            proven_compact_list.verify_and_expand(&crs, &public_key, &metadata)?;
        let a: tfhe::FheUint64 = expander.get(0)?.unwrap();
        let b: tfhe::FheUint64 = expander.get(1)?.unwrap();

        a + b
    };

    // Back on the client side
    let a_plus_b: u64 = result.decrypt(&client_key);
    assert_eq!(a_plus_b, clear_a.wrapping_add(clear_b));

    Ok(())
}
```

## Benchmark 
Please refer to the [Zero-knowledge proof benchmarks](../getting_started/benchmarks/zk_proof_benchmarks.md) for detailed performance benchmark results.

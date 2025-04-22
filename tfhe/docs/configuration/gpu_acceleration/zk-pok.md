# Zero-knowledge proofs

This document explains how to speed up the verification of zero-knowledge proofs using the GPU, similar to how it's done on the [CPU](../../fhe-computation/advanced-features/zk-pok.md).

A proven compact list of ciphertexts can be used to verify the encryption process and then be expanded into a regular list of ciphertexts. 
Currently, only the expansion can be directly accelerated using the GPU. However, verification can be executed on the CPU concurrently with the expansion, making the overall workflow faster.

## Supported types
Encrypted messages can be integers (as FheUint64) or booleans. The GPU backend does not currently support encrypted strings.
{% hint style="info" %}
You can enable this feature using the flag: `--features=zk-pok,gpu` when building **TFHE-rs**.
{% endhint %}

Moreover, the GPU backend better performs when Multi-bit PBS parameters are used, as 
    `tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128`. However, regular classical PBS parameters are also supported.

## Example

The following example shows how a client can encrypt and prove a ciphertext, and how a server can verify and compute the ciphertext on the GPU:

```rust
use rand::random;
use tfhe::CompressedServerKey;
use tfhe::prelude::*;
use tfhe::set_server_key;
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad};

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    let params = tfhe::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    // Indicate which parameters to use for the Compact Public Key encryption
    let cpk_params = tfhe::shortint::parameters::PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    // And parameters allowing to keyswitch/cast to the computation parameters.
    let casting_params = tfhe::shortint::parameters::PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    // Enable the dedicated parameters on the config
    let config = tfhe::ConfigBuilder::with_custom_parameters(params)
        .use_dedicated_compact_public_key_parameters((cpk_params, casting_params)).build();

    // The CRS should be generated in an offline phase then shared to all clients and the server
    let crs = CompactPkeCrs::from_config(config, 64).unwrap();

    // Then use TFHE-rs as usual
    let client_key = tfhe::ClientKey::generate(config);
    let compressed_server_key = CompressedServerKey::new(&client_key);
    let gpu_server_key = compressed_server_key.decompress_to_gpu();
    let public_key = tfhe::CompactPublicKey::try_new(&client_key).unwrap();
    // This can be left empty, but if provided allows to tie the proof to arbitrary data
    let metadata = [b'T', b'F', b'H', b'E', b'-', b'r', b's'];

    let clear_a = random::<u64>();
    let clear_b = random::<u64>();

    let proven_compact_list = tfhe::ProvenCompactCiphertextList::builder(&public_key)
        .push(clear_a)
        .push(clear_b)
        .build_with_proof_packed(&crs, &metadata, ZkComputeLoad::Verify)?;

    // Server side
    let result = {
        set_server_key(gpu_server_key);

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
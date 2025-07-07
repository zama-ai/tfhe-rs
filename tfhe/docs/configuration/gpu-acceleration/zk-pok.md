# Zero-knowledge proofs

Zero-knowledge proofs (ZK) are a powerful tool to assert that the encryption of a message is correctly formed with secure cryptographic parameters and helps thwart chosen ciphertext attacks (CCA) such as replay attacks. 

The CPU implementation is discussed in [advanced features](../../fhe-computation/advanced-features/zk-pok.md). During encryption, ZK proofs can be generated for a single ciphertext or for a list of ciphertexts. To use ciphertexts with proofs for computation, additional conversion steps are needed: proof expansion and proof verification. While both steps are necessary to use ciphertexts with proofs for computation, only proof expansion is sped up on GPU, while verification is performed by the CPU.

## Configuration

{% hint style="info" %}
You can enable this feature using the flag: `--features=zk-pok,gpu` when building **TFHE-rs**.
{% endhint %}

## API elements discussed in this document

- [`tfhe::ProvenCompactCiphertextList`](https://docs.rs/tfhe/latest/tfhe/struct.ProvenCompactCiphertextList.html): a list of ciphertexts with accompanying ZK-proofs. The ciphertexts are stored in a compact form and must be expanded for computation.
- [`tfhe::ProvenCompactCiphertextList::verify_and_expand`](https://docs.rs/tfhe/latest/tfhe/struct.ProvenCompactCiphertextList.html#method.verify_and_expand): verify the proofs for this ciphertext list and expand each ciphertext into a form that is supported for computation.

## Proven compact ciphertext list

A proven compact list of ciphertexts can be seen as a compacted collection of ciphertexts for which encryption can be verified.
This verification is currently only supported on the CPU, but the expansion can be sped up using the GPU. However, verification and expansion can be performed in parallel, efficiently using all the available computational resources.

## Supported types
Encrypted messages can be integers (like FheUint64) or booleans. The GPU backend does not currently support encrypted strings.

## Example

The following example shows how a client can encrypt and prove a ciphertext, and how a server can verify the proof, preprocess the ciphertext and run a computation on it on GPU:

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

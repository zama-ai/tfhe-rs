# Zero-knowledge proofs

Zero-knowledge proofs (ZK) verify that ciphertext encryption is correctly formed with secure parameters, helping thwart chosen ciphertext attacks (CCA) such as replay attacks. For a full introduction to ZK proofs in **TFHE-rs**, see the [CPU documentation](../../fhe-computation/advanced-features/zk-pok.md).

The GPU backend accelerates three ZK-related operations:

- **Proof generation** and **verification**: offloads the compute-intensive parts of the ZK algorithms to the GPU.
- **Compact ciphertext expansion**: converts compact ciphertexts into a form usable for computation once the proof is verified as valid.

Proof verification and compact ciphertext expansion are independent and can run concurrently.

## Configuration

{% hint style="info" %}
For GPU-accelerated **expansion only**, build with:
```shell
--features=zk-pok,gpu
```
{% endhint %}

{% hint style="warning" %}
For GPU-accelerated **proof generation** and **verification**, build with:
```shell
--features=gpu-experimental-zk
```
This feature implies `gpu` and `zk-pok`, so you do not need to specify them separately. It requires a CUDA-capable GPU. This feature is experimental and should not be used in production.
{% endhint %}

The Rust API is identical in both cases. The `gpu-experimental-zk` feature flag switches the internal dispatch for proof generation and verification from CPU to GPU at compile time, so no code changes are needed beyond the feature flag.

## API elements discussed in this document

- [`tfhe::zk::CompactPkeCrs`](https://docs.rs/tfhe/latest/tfhe/zk/enum.CompactPkeCrs.html): the Common Reference String (CRS) shared between prover and verifier. Generated once during an offline setup phase.
- [`tfhe::zk::ZkComputeLoad`](https://docs.rs/tfhe/latest/tfhe/zk/enum.ZkComputeLoad.html): controls whether the heavier computation is placed on the prover or the verifier.
- [`tfhe::ProvenCompactCiphertextList`](https://docs.rs/tfhe/latest/tfhe/struct.ProvenCompactCiphertextList.html): a list of ciphertexts with accompanying ZK proofs, stored in compact form.
- [`tfhe::ProvenCompactCiphertextList::builder`](https://docs.rs/tfhe/latest/tfhe/struct.ProvenCompactCiphertextList.html#method.builder): creates a builder for encrypting values and generating a proof via `build_with_proof_packed`.
- [`tfhe::ProvenCompactCiphertextList::verify_and_expand`](https://docs.rs/tfhe/latest/tfhe/struct.ProvenCompactCiphertextList.html#method.verify_and_expand): verifies the proofs and expands each ciphertext into a form usable for computation.

## GPU-accelerated operations

GPU acceleration is manifested in different ways depending on the operation.

### Proof generation and verification

If the `gpu-experimental-zk` feature is active, the compute-intensive parts of proof generation and verification are offloaded to the GPU, producing proofs bitwise compatible with the CPU implementation. This is supported only for the PKE v2 scheme, which is selected by default with current parameters.

When multiple GPUs are available, ZK operations automatically distribute work across them.

### Compact ciphertext expansion

A verified valid compact ciphertext must be expanded before it can be used in FHE computations. The GPU accelerates this expansion step if the feature `gpu` is active. Expansion and proof verification are independent and can run concurrently.

## Supported types

Encrypted messages can be integers (such as `FheUint64`) or booleans (`FheBool`). The GPU backend does not currently support encrypted strings.

## Example

The following example shows how a client can encrypt and prove a ciphertext, and how a server can verify the proof, expand the ciphertext, and run a computation on GPU:

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

        // Verify the proofs and expand the ciphertexts
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

{% hint style="info" %}
When built with `--features=gpu-experimental-zk`, the `build_with_proof_packed` and `verify_and_expand` calls in this same code will automatically use the GPU for proof generation, verification, and ciphertext expansion. If built with `--features=gpu`, only ciphertext expansion will be accelerated by the GPU. No code changes are required.
{% endhint %}

## Benchmark

Please refer to the [Zero-knowledge proof benchmarks](../../getting-started/benchmarks/zk-proof-benchmarks.md) for detailed performance results.

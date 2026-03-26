# Zero-knowledge proofs

Zero-knowledge proofs (ZK) verify that ciphertext encryption is correctly formed with secure parameters, helping thwart chosen ciphertext attacks (CCA) such as replay attacks. For a full introduction to ZK proofs in **TFHE-rs**, see the [CPU documentation](../../fhe-computation/advanced-features/zk-pok.md).

The GPU backend accelerates ZK-related operations at two levels:

- **Stable**: GPU-accelerated **expansion** of compact ciphertexts into a form usable for computation. Proof verification remains completely executed by the CPU.
- **Experimental**: GPU-accelerated **proof generation** and **proof verification**, where compute-intensive parts of the algorithms are offloaded to the GPU. This also includes the expansion acceleration from the stable tier.

In both cases proof verification and compact ciphertext expansion are independent and can be computed concurrently.

## Configuration

{% hint style="info" %}
For GPU-accelerated **expansion only** (stable), build with:
```
--features=zk-pok,gpu
```
{% endhint %}

{% hint style="warning" %}
For GPU-accelerated **proof generation and verification** (experimental), build with:
```
--features=gpu-experimental-zk
```
This feature implies `gpu` and `zk-pok`, so you do not need to specify them separately. It requires a CUDA-capable GPU. This feature is experimental and should not be used in production.
{% endhint %}

The Rust API is identical for both tiers. The `gpu-experimental-zk` feature flag switches the internal dispatch for proof generation and verification from CPU to GPU at compile time, so no code changes are needed beyond the feature flag.

## API elements discussed in this document

- [`tfhe::ProvenCompactCiphertextList`](https://docs.rs/tfhe/latest/tfhe/struct.ProvenCompactCiphertextList.html): a list of ciphertexts with accompanying ZK-proofs. The ciphertexts are stored in a compact form and must be expanded for computation.
- [`tfhe::ProvenCompactCiphertextList::verify_and_expand`](https://docs.rs/tfhe/latest/tfhe/struct.ProvenCompactCiphertextList.html#method.verify_and_expand): verify the proofs for this ciphertext list and expand each ciphertext into a form that is supported for computation.

## GPU-accelerated operations

### Compact ciphertext expansion (stable)

Proven compact ciphertexts must be expanded before they can be used in FHE computations. The GPU accelerates this expansion step. Proof verification is performed on the CPU, but it runs in parallel with expansion, efficiently using all available computational resources.

### Proof generation and verification (experimental)

With the `gpu-experimental-zk` feature, the most compute-intensive parts of proof generation and proof verification are offloaded to the GPU. This applies to the PKE v2 scheme, which is selected by default with current parameters.

When multiple GPUs are available, ZK operations automatically distribute work across them.

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

{% hint style="info" %}
When built with `--features=gpu-experimental-zk`, the `build_with_proof_packed` and `verify_and_expand` calls in this same code will automatically use the GPU for proof generation and verification respectively. No code changes are required.
{% endhint %}

## Benchmark

Please refer to the [Zero-knowledge proof benchmarks](../../getting-started/benchmarks/zk-proof-benchmarks.md) for detailed performance results.

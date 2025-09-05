# Noise squashing

For security reasons, threshold decryption may require adding large amounts of random noise to ciphertext. Noise squashing is a technique applied beforehand to make space for that additional noise. Even after adding this extra random noise, decryption remains correct.

**TFHE-rs**' High Level API provides APIs to do just that. In [advanced features](../../fhe-computation/advanced-features/noise-squashing.md), you can read about the CPU implementation of noise squashing. However, that operation can be accelerated through GPUs. This document describes how one can do that.

## Configuration

{% hint style="info" %}
You can enable this feature using the flag: `--features=gpu` when building **TFHE-rs**.
{% endhint %}

## Example

As with other operations, to enable GPU acceleration, one just needs to set the GPU server key as follows:

```rust
use tfhe::prelude::*;
use tfhe::shortint::parameters::{
    PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    NOISE_SQUASHING_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128
};
use tfhe::*;

// We use an identity function to verify FHE operations, it is fine in this context
#[allow(clippy::eq_op)]
pub fn main() {
    // Configure computations enabling the noise squashing capability.
    let config =
        ConfigBuilder::with_custom_parameters(PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .enable_noise_squashing(NOISE_SQUASHING_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .build();

    // Generate the keys
    let cks = crate::ClientKey::generate(config);
    let sks = cks.generate_compressed_server_key();

    // Set the GPU key once for our various examples
    set_server_key(sks.decompress_to_gpu());

    // FheUint32 case
    let clear: u32 = 42;
    // Encrypt
    let enc = FheUint32::encrypt(clear, &cks);
    // Simulate a bitand on the blockchain
    let bitand = &enc & &enc;
    // Perform the noise squashing
    let squashed = bitand.squash_noise().unwrap();

    // We don't perform the noise flooding, but here verify that the noise squashing preserves our
    // data
    let recovered: u32 = squashed.decrypt(&cks);

    assert_eq!(clear, recovered);

    // FheInt16 case
    let clear: i16 = -42;
    let enc = FheInt10::encrypt(clear, &cks);
    let bitand = &enc & &enc;
    let squashed = bitand.squash_noise().unwrap();

    let recovered: i16 = squashed.decrypt(&cks);
    assert_eq!(clear, recovered);

    // Boolean case
    for clear in [false, true] {
        let enc = FheBool::encrypt(clear, &cks);
        let bitand = &enc & &enc;
        let squashed = bitand.squash_noise().unwrap();

        let recovered: bool = squashed.decrypt(&cks);
        assert_eq!(clear, recovered);
    }
}

```

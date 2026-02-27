# Noise squashing

In the context of confidential blockchain protocols, like the [Zama protocol](https://docs.zama.org/protocol), for security reasons the threshold decryption requires to hide the intrinsic noise of FHE operations. This can be achieved by the MPC nodes by adding large amounts of random noise before they perform the actual decryption. In order to have enough room for that large noise that needs to be added before decryption, the noise squashing operation is performed.

**TFHE-rs**' High Level API provides APIs to do just that, here is how one would use those primitives:

```rust
use tfhe::prelude::*;
use tfhe::shortint::parameters::{
    NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use tfhe::*;

// We use an identity function to verify FHE operations, it is fine in this context
#[allow(clippy::eq_op)]
pub fn main() {
    // Configure computations enabling the noise squashing capability.
    let config =
        ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .enable_noise_squashing(NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .build();

    // Generate the keys
    let (cks, sks) = generate_keys(config);

    // Set the key once for our various examples
    set_server_key(sks);

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

## Compression
Like regular ciphertexts, squashed noise ciphertexts can be stored into a list and compressed to reduce their size.

To do that, use `CompressedSquashedNoiseCiphertextList::builder`:
```rust
use tfhe::prelude::*;
use tfhe::shortint::parameters::{
    NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use tfhe::*;

// We use an identity function to verify FHE operations, it is fine in this context
#[allow(clippy::eq_op)]
pub fn main() {
    // Configure computations enabling the noise squashing capability.
    let config =
        ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .enable_noise_squashing(NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .enable_noise_squashing_compression(NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .build();

    // Generate the keys
    let (cks, sks) = generate_keys(config);

    // Set the key once for our various examples
    set_server_key(sks);

    // Encrypt some values
    let clear_a: i32 = -42;
    let clear_b: u32 = 1025;
    let clear_c = false;

    let a = FheInt32::encrypt(clear_a, &cks);
    let b = FheUint32::encrypt(clear_b, &cks);
    let c = FheBool::encrypt(clear_c, &cks);

    // Squash the noise
    let squashed_a = a.squash_noise().unwrap();
    let squashed_b = b.squash_noise().unwrap();
    let squashed_c = c.squash_noise().unwrap();

    // Store ciphertexts into a list and compress them
    let list = CompressedSquashedNoiseCiphertextList::builder()
        .push(squashed_a)
        .push(squashed_b)
        .push(squashed_c)
        .build()
        .unwrap();

    // Extract and decompress the ciphertexts
    let squashed_a: SquashedNoiseFheInt = list.get(0).unwrap().unwrap();
    let squashed_b: SquashedNoiseFheUint = list.get(1).unwrap().unwrap();
    let squashed_c: SquashedNoiseFheBool = list.get(2).unwrap().unwrap();

    // Decrypt them
    let decrypted: i32 = squashed_a.decrypt(&cks);
    assert_eq!(decrypted, clear_a);

    let decrypted: u32 = squashed_b.decrypt(&cks);
    assert_eq!(decrypted, clear_b);

    let decrypted: bool = squashed_c.decrypt(&cks);
    assert_eq!(decrypted, clear_c);
}

```

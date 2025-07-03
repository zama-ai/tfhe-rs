# Noise squashing

In the context of confidential blockchain protocols, like the [Zama protocol](https://docs.zama.ai/protocol), for security reasons the threshold decryption requires to hide the intrinsic noise of FHE operations. This can be achieved by the MPC nodes by adding large amounts of random noise before they perform the actual decryption. In order to have enough room for that large noise that needs to be added before decryption, the noise squashing operation is performed.

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

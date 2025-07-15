# Upgrade Key Chain

This document describes how one can use the `UpgradeKeyChain` to be able to
easily upgrade a ciphertext that is under older parameters to newer parameters.

It is different and complementary to the data versioning feature, as the
data versioning feature allows loading ciphertexts generated
with a previous TFHE-rs version if the ciphertext structurally changed.


The `UpgradeKeyChain` first needs to know about possible parameters, for that,
`add_key_set` should be called with all the different server keys.
Note that the `Tag` of the keys is used to differentiate them.

Then, the `UpgradeKeyChain` requires upgrade keys to be able to upgrade ciphertexts,
there are two types of these keys:
- `KeySwitchingKey` to upgrade a FheUint/FheInt/FheBool to another FheUint/FheInt/FheBool with different parameters
- `DecompressionUpgradeKey` to upgrade ciphertexts from a `CompressedCiphertextList` to FheUint/FheInt/FheBool with different parameters


```rust
use tfhe::shortint::parameters::{
    COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use tfhe::prelude::*;
use tfhe::{ConfigBuilder, set_server_key, ServerKey, ClientKey, FheUint32, KeySwitchingKey, Device};
use tfhe::upgrade::UpgradeKeyChain;

fn main() {
    let compute_params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let compression_parameters = COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let config = ConfigBuilder::with_custom_parameters(compute_params)
        .enable_compression(compression_parameters)
        .build();

    let (cks_1, sks_1) = {
        let mut ck = ClientKey::generate(config);
        ck.tag_mut().set_u64(1);
        let sk = ServerKey::new(&ck);
        (ck, sk)
    };

    let (cks_2, sks_2) = {
        let mut ck = ClientKey::generate(config);
        ck.tag_mut().set_u64(2);
        let sk = ServerKey::new(&ck);
        (ck, sk)
    };

    // Create a ksk that upgrades from the first key, to the second key
    let ksk = KeySwitchingKey::with_parameters(
        (&cks_1, &sks_1),
        (&cks_2, &sks_2),
        PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    );

    let mut upgrader = UpgradeKeyChain::default();
    // First, add the server keys
    // to register the different possible parameters
    upgrader.add_key_set(&sks_1);
    upgrader.add_key_set(&sks_2);
    // Add our upgrade key
    upgrader.add_upgrade_key(ksk).unwrap();
    

    let clear_a = rand::random::<u32>();
    let clear_b = rand::random::<u32>();
    
    let a = FheUint32::encrypt(clear_a, &cks_1);
    let b = FheUint32::encrypt(clear_b, &cks_1);

    let upgraded_a = upgrader
        .upgrade(&a, sks_2.tag(), Device::Cpu)
        .unwrap();

    let upgraded_b = upgrader
        .upgrade(&b, sks_2.tag(), Device::Cpu)
        .unwrap();

    set_server_key(sks_2.clone());
    let c = upgraded_a + upgraded_b;
    let dc: u32 = c.decrypt(&cks_2);
    assert_eq!(dc, clear_a.wrapping_add(clear_b));
}
```

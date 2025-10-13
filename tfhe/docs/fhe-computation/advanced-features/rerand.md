# Ciphertext Re-Randomization

In the paper [Drifting Towards Better Error Probabilities in Fully Homomorphic Encryption Schemes](https://eprint.iacr.org/2024/1718), Bernard et al. introduced the sIND-CPA^D security model (`s` stands for strong here).

This document explains the ciphertext re-randomization feature in TFHE-rs, designed to protect FHE computations against attacks under the sIND-CPA^D security model.

To be secure under that model, **TFHE-rs** provides a re-randomization primitive that allows users to re-randomize ciphertexts before they are used as inputs to a predefined FHE program `F`. In this context, `F` should be understood as any FHE computation that must remain secure under the sIND-CPA^D model. All encrypted inputs to `F` must be re-randomized prior to execution.


## Example: Re-randomization of two `FheUint64` values before addition

```rust
use tfhe::prelude::*;
use tfhe::shortint::parameters::v1_4::meta::cpu::V1_4_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128;
use tfhe::{
    generate_keys, set_server_key, CompactPublicKey, CompressedCiphertextListBuilder, FheUint64,
    ReRandomizationContext,
};

pub fn main() {
    // The chosen parameters have re-rand enabled
    let (cks, sks) = generate_keys(V1_4_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128);
    let cpk = CompactPublicKey::new(&cks);

    let compact_public_encryption_domain_separator = *b"TFHE_Enc";
    let rerand_domain_separator = *b"TFHE_Rrd";

    set_server_key(sks);

    // We want to compute FheUint64 + FheUint64, prepare inputs
    let clear_a = rand::random::<u64>();
    let clear_b = rand::random::<u64>();
    let a = FheUint64::encrypt(clear_a, &cks);
    let b = FheUint64::encrypt(clear_b, &cks);

    // Simulate the data being stored on disk
    let mut builder = CompressedCiphertextListBuilder::new();
    builder.push(a);
    builder.push(b);
    let list = builder.build().unwrap();

    // Actual Re-Randomization context
    let c = {
        // Inputs are fetched from storage
        let mut a: FheUint64 = list.get(0).unwrap().unwrap();
        let mut b: FheUint64 = list.get(1).unwrap().unwrap();

        // Simulate a 256 bits nonce to make the execution unique
        let nonce: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());

        let mut re_rand_context = ReRandomizationContext::new(
            rerand_domain_separator,
            // First is the function description, second is a nonce
            [b"FheUint64+FheUint64".as_slice(), nonce.as_slice()],
            compact_public_encryption_domain_separator,
        );

        // Add ciphertexts to the context
        re_rand_context.add_ciphertext(&a);
        re_rand_context.add_ciphertext(&b);

        // Get the seeds for the rerandomization
        let mut seed_gen = re_rand_context.finalize();

        // Re-Randomize a and b
        a.re_randomize(&cpk, seed_gen.next_seed().unwrap()).unwrap();
        b.re_randomize(&cpk, seed_gen.next_seed().unwrap()).unwrap();

        // Compute our function F
        a + b
    };

    // Check everything went well
    let dec: u64 = c.decrypt(&cks);
    assert_eq!(clear_a.wrapping_add(clear_b), dec);
}
```

Note that if ciphertexts require auxiliary metadata to perform the re-randomization, those can be added on the ciphertext using the `re_randomization_metadata_mut` accessors and then calling the `set_data` function on it:

```rust
use tfhe::prelude::*;
use tfhe::shortint::parameters::v1_4::meta::cpu::V1_4_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128;
use tfhe::{ClientKey, FheUint64};

pub fn main() {
    let cks = ClientKey::generate(V1_4_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128);

    let clear_a = rand::random::<u64>();
    let mut a = FheUint64::encrypt(clear_a, &cks);

    // Generate some random metadata simulating a 256 bits hash
    let rand_a: [u8; 256 / 8] = core::array::from_fn(|_| rand::random());

    // Add it to the ciphertext a
    a.re_randomization_metadata_mut().set_data(&rand_a);
}
```

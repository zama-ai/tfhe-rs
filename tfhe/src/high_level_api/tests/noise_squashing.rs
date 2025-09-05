use crate::high_level_api::prelude::*;
use crate::high_level_api::{
    generate_keys, ConfigBuilder, FheBool, FheInt10, FheInt8, FheUint256, FheUint32,
};
use crate::integer::U256;
use crate::set_server_key;
#[cfg(feature = "gpu")]
use crate::shortint::parameters::{
    NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    NOISE_SQUASHING_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use crate::shortint::parameters::{
    NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};

use rand::prelude::*;

#[test]
fn test_noise_squashing() {
    let config =
        ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .enable_noise_squashing(NOISE_SQUASHING_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .build();
    let (cks, sks) = generate_keys(config);

    set_server_key(sks);

    let mut rng = thread_rng();

    // Non native type for clear
    let clear: U256 = rng.gen();
    let enc = FheUint256::encrypt(clear, &cks);
    let bitand = &enc & &enc;

    let squashed = bitand.squash_noise().unwrap();

    let recovered: U256 = squashed.decrypt(&cks);

    assert_eq!(clear, recovered);

    // Native unsigned
    let clear: u32 = rng.gen();
    let enc = FheUint32::encrypt(clear, &cks);
    let bitand = &enc & &enc;

    let squashed = bitand.squash_noise().unwrap();

    let recovered: u32 = squashed.decrypt(&cks);

    assert_eq!(clear, recovered);

    // Non native signed with proper input range
    let clear: i16 = rng.gen_range(-1 << 9..1 << 9);
    let enc = FheInt10::encrypt(clear, &cks);
    let bitand = &enc & &enc;

    let squashed = bitand.squash_noise().unwrap();

    let recovered: i16 = squashed.decrypt(&cks);
    assert_eq!(clear, recovered);

    // Native signed
    let clear: i8 = rng.gen();
    let enc = FheInt8::encrypt(clear, &cks);
    let bitand = &enc & &enc;

    let squashed = bitand.squash_noise().unwrap();

    let recovered: i8 = squashed.decrypt(&cks);
    assert_eq!(clear, recovered);

    // Booleans
    for clear in [false, true] {
        let enc = FheBool::encrypt(clear, &cks);
        let bitand = &enc & &enc;

        let squashed = bitand.squash_noise().unwrap();

        let recovered: bool = squashed.decrypt(&cks);
        assert_eq!(clear, recovered);
    }
}
#[cfg(feature = "gpu")]
#[test]
fn test_gpu_noise_squashing() {
    let noise_squashing_params = [
        NOISE_SQUASHING_PARAM_GPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        NOISE_SQUASHING_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    ];

    for noise_squashing_param in noise_squashing_params {
        let config = ConfigBuilder::with_custom_parameters(
        crate::shortint::parameters::PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
        .enable_noise_squashing(noise_squashing_param)
        .build();
        let cks = crate::ClientKey::generate(config);
        let sks = cks.generate_compressed_server_key();
        set_server_key(sks.decompress_to_gpu());

        let mut rng = thread_rng();

        // Non native type for clear
        let clear: U256 = rng.gen();
        let enc = FheUint256::encrypt(clear, &cks);
        let bitand = &enc & &enc;

        let squashed = bitand.squash_noise().unwrap();

        let recovered: U256 = squashed.decrypt(&cks);
        assert_eq!(clear, recovered);

        // Native unsigned
        let clear: u32 = rng.gen();
        let enc = FheUint32::encrypt(clear, &cks);
        let bitand = &enc & &enc;

        let squashed = bitand.squash_noise().unwrap();

        let recovered: u32 = squashed.decrypt(&cks);
        assert_eq!(clear, recovered);

        // Non native signed with proper input range
        let clear: i16 = rng.gen_range(-1 << 9..1 << 9);
        let enc = FheInt10::encrypt(clear, &cks);
        let bitand = &enc & &enc;

        let squashed = bitand.squash_noise().unwrap();

        let recovered: i16 = squashed.decrypt(&cks);
        assert_eq!(clear, recovered);

        // Native signed
        let clear: i8 = rng.gen();
        let enc = FheInt8::encrypt(clear, &cks);
        let bitand = &enc & &enc;

        let squashed = bitand.squash_noise().unwrap();

        let recovered: i8 = squashed.decrypt(&cks);
        assert_eq!(clear, recovered);

        // Booleans
        for clear in [false, true] {
            let enc = FheBool::encrypt(clear, &cks);
            let bitand = &enc & &enc;

            let squashed = bitand.squash_noise().unwrap();

            let recovered: bool = squashed.decrypt(&cks);
            assert_eq!(clear, recovered);
        }
    }
}

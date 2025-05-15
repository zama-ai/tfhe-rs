use crate::high_level_api::prelude::*;
use crate::high_level_api::{
    generate_keys, ConfigBuilder, FheBool, FheInt10, FheInt8, FheUint256, FheUint32,
};
use crate::integer::U256;
use crate::set_server_key;
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

    let mut rng = rand::rng();

    // Non native type for clear
    let clear: U256 = rng.random();
    let enc = FheUint256::encrypt(clear, &cks);
    let bitand = &enc & &enc;

    let squashed = bitand.squash_noise().unwrap();

    let recovered: U256 = squashed.decrypt(&cks);
    assert_eq!(clear, recovered);

    // Native unsigned
    let clear: u32 = rng.random();
    let enc = FheUint32::encrypt(clear, &cks);
    let bitand = &enc & &enc;

    let squashed = bitand.squash_noise().unwrap();

    let recovered: u32 = squashed.decrypt(&cks);
    assert_eq!(clear, recovered);

    // Non native signed with proper input range
    let clear: i16 = rng.random_range(-1 << 9..1 << 9);
    let enc = FheInt10::encrypt(clear, &cks);
    let bitand = &enc & &enc;

    let squashed = bitand.squash_noise().unwrap();

    let recovered: i16 = squashed.decrypt(&cks);
    assert_eq!(clear, recovered);

    // Native signed
    let clear: i8 = rng.random();
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

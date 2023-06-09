use crate::high_level_api::prelude::*;
use crate::high_level_api::{
    generate_keys, set_server_key, CompressedFheUint2, ConfigBuilder, FheUint2,
};
use crate::{CastingKey, CompressedPublicKey};

#[test]
fn test_shortint_compressed() {
    let config = ConfigBuilder::all_disabled().enable_default_uint2().build();
    let (client_key, _) = generate_keys(config);

    let compressed: CompressedFheUint2 = CompressedFheUint2::try_encrypt(2, &client_key).unwrap();
    let a = FheUint2::from(compressed);
    let decompressed = a.decrypt(&client_key);
    assert_eq!(decompressed, 2);
}

#[test]
fn test_shortint_compressed_public_key() {
    let config = ConfigBuilder::all_disabled().enable_default_uint2().build();
    let (client_key, _) = generate_keys(config);

    let public_key = CompressedPublicKey::new(&client_key);

    let a = FheUint2::try_encrypt(2, &public_key).unwrap();
    let clear = a.decrypt(&client_key);
    assert_eq!(clear, 2);
}

#[test]
fn test_trivial_shortint() {
    let config = ConfigBuilder::all_disabled().enable_default_uint2().build();
    let (client_key, sks) = generate_keys(config);

    set_server_key(sks);

    let a = FheUint2::try_encrypt_trivial(2).unwrap();
    let clear = a.decrypt(&client_key);
    assert_eq!(clear, 2);
}

#[test]
fn test_cast_shortint() {
    let config = ConfigBuilder::all_disabled().enable_default_uint2().build();
    let (client_key_1, server_key_1) = generate_keys(config.clone());
    let (client_key_2, server_key_2) = generate_keys(config);

    let ksk = CastingKey::new(
        (&client_key_1, &server_key_1),
        (&client_key_2, &server_key_2),
    );

    let mut a = FheUint2::try_encrypt(3, &client_key_1).unwrap();
    a = a.cast(&ksk);
    let clear = a.decrypt(&client_key_2);
    assert_eq!(clear, 3);
}

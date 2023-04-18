use crate::high_level_api::prelude::*;
use crate::high_level_api::{
    generate_keys, set_server_key, CompressedFheUint2, ConfigBuilder, FheUint2,
};
use crate::CompressedPublicKey;

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

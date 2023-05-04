use crate::high_level_api::prelude::*;
#[cfg(feature = "boolean")]
use crate::high_level_api::FheBool;
#[cfg(feature = "shortint")]
use crate::high_level_api::FheUint2;
#[cfg(any(feature = "boolean", feature = "shortint", feature = "integer"))]
use crate::high_level_api::{generate_keys, ClientKey, ConfigBuilder, PublicKey};
#[cfg(feature = "integer")]
use crate::high_level_api::{FheUint256, FheUint8};
#[cfg(feature = "integer")]
use crate::integer::U256;
use crate::CompressedPublicKey;
#[cfg(any(feature = "boolean", feature = "shortint", feature = "integer"))]
use std::fmt::Debug;

#[cfg(any(feature = "boolean", feature = "shortint", feature = "integer"))]
fn assert_that_public_key_encryption_is_decrypted_by_client_key<FheType, ClearType>(
    clear: ClearType,
    pks: &PublicKey,
    cks: &ClientKey,
) where
    ClearType: Copy + Eq + Debug,
    FheType: FheTryEncrypt<ClearType, PublicKey> + FheDecrypt<ClearType>,
{
    let encrypted = FheType::try_encrypt(clear, pks).unwrap();
    let decrypted: ClearType = encrypted.decrypt(cks);
    assert_eq!(clear, decrypted);
}

#[cfg(feature = "boolean")]
#[test]
fn test_boolean_public_key() {
    let config = ConfigBuilder::all_disabled().enable_default_bool().build();

    let (cks, _sks) = generate_keys(config);

    let pks = PublicKey::new(&cks);

    assert_that_public_key_encryption_is_decrypted_by_client_key::<FheBool, bool>(
        false, &pks, &cks,
    );
    assert_that_public_key_encryption_is_decrypted_by_client_key::<FheBool, bool>(true, &pks, &cks);
}

#[cfg(feature = "shortint")]
#[test]
fn test_shortint_public_key() {
    let config = ConfigBuilder::all_disabled().enable_default_uint2().build();

    let (cks, _sks) = generate_keys(config);

    let pks = PublicKey::new(&cks);

    assert_that_public_key_encryption_is_decrypted_by_client_key::<FheUint2, u8>(0, &pks, &cks);
    assert_that_public_key_encryption_is_decrypted_by_client_key::<FheUint2, u8>(1, &pks, &cks);
    assert_that_public_key_encryption_is_decrypted_by_client_key::<FheUint2, u8>(2, &pks, &cks);
    assert_that_public_key_encryption_is_decrypted_by_client_key::<FheUint2, u8>(3, &pks, &cks);
}

#[cfg(feature = "integer")]
#[test]
fn test_integer_public_key() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();

    let (cks, _sks) = generate_keys(config);

    let pks = PublicKey::new(&cks);

    assert_that_public_key_encryption_is_decrypted_by_client_key::<FheUint8, u8>(235, &pks, &cks);
}

#[cfg(feature = "integer")]
#[test]
fn test_small_uint8() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers_small()
        .build();

    let (cks, _sks) = generate_keys(config);

    let pks = PublicKey::new(&cks);

    assert_that_public_key_encryption_is_decrypted_by_client_key::<FheUint8, u8>(235, &pks, &cks);
}

#[cfg(feature = "integer")]
#[test]
fn test_small_uint256() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers_small()
        .build();

    let (cks, _sks) = generate_keys(config);

    let pks = PublicKey::new(&cks);

    use rand::prelude::*;
    let mut rng = rand::thread_rng();
    let value = rng.gen::<U256>();
    assert_that_public_key_encryption_is_decrypted_by_client_key::<FheUint256, U256>(
        value, &pks, &cks,
    );
}

#[cfg(feature = "boolean")]
#[test]
fn test_with_context() {
    let config = ConfigBuilder::all_disabled().enable_default_bool().build();

    let (cks, sks) = generate_keys(config);

    let a = FheBool::encrypt(false, &cks);
    let b = FheBool::encrypt(true, &cks);

    let (r, _) = crate::high_level_api::with_server_key_as_context(sks, move || a & b);
    let d = r.decrypt(&cks);
    assert!(!d);
}

/// The purpose of this test is to assert that
/// the deserialize and serialize traits are implemented
#[test]
fn test_serialize_deserialize_are_implemented() {
    let config = ConfigBuilder::all_disabled().build();

    fn can_be_deserialized<T: serde::de::DeserializeOwned + serde::Serialize>(object: &T) {
        let data = bincode::serialize(object).unwrap();
        let _o: T = bincode::deserialize_from(data.as_slice()).unwrap();
    }

    let (cks, sks) = generate_keys(config);
    let pks = PublicKey::new(&cks);
    let cpks = CompressedPublicKey::new(&cks);

    can_be_deserialized(&cks);
    can_be_deserialized(&sks);
    can_be_deserialized(&pks);
    can_be_deserialized(&cpks);
}

use crate::high_level_api::prelude::*;
#[cfg(feature = "boolean")]
use crate::high_level_api::FheBool;
#[cfg(any(feature = "boolean", feature = "shortint", feature = "integer"))]
use crate::high_level_api::{generate_keys, ClientKey, ConfigBuilder, PublicKey};
#[cfg(feature = "integer")]
use crate::high_level_api::{FheUint256, FheUint8};
#[cfg(feature = "integer")]
use crate::integer::U256;
use crate::{CompactPublicKey, CompressedPublicKey, CompressedServerKey};
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

#[cfg(feature = "integer")]
#[test]
fn test_server_key_decompression() -> Result<(), Box<dyn std::error::Error>> {
    use crate::set_server_key;

    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();

    let cks = ClientKey::generate(config);
    let compressed_sks = CompressedServerKey::new(&cks);
    let sks = compressed_sks.decompress();

    set_server_key(sks);

    let clear_a = 12u8;
    let a = FheUint8::try_encrypt(clear_a, &cks)?;

    let c = a + 234u8;
    let decrypted: u8 = c.decrypt(&cks);
    assert_eq!(decrypted, clear_a.wrapping_add(234));

    Ok(())
}

#[test]
fn test_with_seed() -> Result<(), Box<dyn std::error::Error>> {
    use crate::Seed;
    let mut builder = ConfigBuilder::all_disabled();
    #[cfg(feature = "integer")]
    {
        builder = builder.enable_default_integers();
    }
    #[cfg(feature = "boolean")]
    {
        builder = builder.enable_default_bool();
    }
    let config = builder.build();

    let cks1 = ClientKey::generate_with_seed(config.clone(), Seed(125));
    let cks2 = ClientKey::generate(config.clone());
    let cks3 = ClientKey::generate_with_seed(config.clone(), Seed(125));
    let cks4 = ClientKey::generate_with_seed(config, Seed(127));

    let cks1_serialized = bincode::serialize(&cks1).unwrap();
    let cks2_serialized = bincode::serialize(&cks2).unwrap();
    let cks3_serialized = bincode::serialize(&cks3).unwrap();
    let cks4_serialized = bincode::serialize(&cks4).unwrap();

    assert_eq!(&cks1_serialized, &cks3_serialized);
    assert_ne!(&cks1_serialized, &cks2_serialized);
    assert_ne!(&cks1_serialized, &cks4_serialized);

    Ok(())
}

#[cfg(feature = "integer")]
#[test]
#[should_panic]
fn test_compressed_server_key_creation_panic_if_function_eval() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .enable_function_evaluation_integers()
        .build();

    let cks = ClientKey::generate(config);
    let _ = CompressedServerKey::new(&cks);
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
    let csks = CompressedServerKey::new(&cks);
    let pksz = CompactPublicKey::new(&cks);

    can_be_deserialized(&cks);
    can_be_deserialized(&sks);
    can_be_deserialized(&pks);
    can_be_deserialized(&cpks);
    can_be_deserialized(&csks);
    can_be_deserialized(&pksz);
}

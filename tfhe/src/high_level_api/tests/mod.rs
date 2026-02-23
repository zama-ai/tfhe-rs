mod cpk_re_randomization;
#[cfg(feature = "gpu")]
mod gpu_selection;
mod noise_distribution;
mod noise_squashing;
mod tags_on_entities;

use crate::high_level_api::prelude::*;
use crate::high_level_api::{
    generate_keys, ClientKey, ConfigBuilder, FheBool, FheUint256, FheUint8, PublicKey, ServerKey,
};
use crate::integer::U256;
use crate::shortint::parameters::TestParameters;
use crate::shortint::ClassicPBSParameters;
use crate::{
    set_server_key, CompactPublicKey, CompressedPublicKey, CompressedServerKey, FheUint32, Tag,
};
use std::fmt::Debug;

pub(crate) fn setup_cpu(params: Option<impl Into<TestParameters>>) -> ClientKey {
    let config = params
        .map_or_else(ConfigBuilder::default, |p| {
            ConfigBuilder::with_custom_parameters(p.into())
        })
        .build();

    let client_key = ClientKey::generate(config);
    let csks = crate::CompressedServerKey::new(&client_key);
    let server_key = csks.decompress();

    set_server_key(server_key);

    client_key
}

pub(crate) fn setup_default_cpu() -> ClientKey {
    setup_cpu(Option::<ClassicPBSParameters>::None)
}

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

#[test]
fn test_boolean_public_key() {
    let config = ConfigBuilder::default().build();

    let (cks, _sks) = generate_keys(config);

    let pks = PublicKey::new(&cks);

    assert_that_public_key_encryption_is_decrypted_by_client_key::<FheBool, bool>(
        false, &pks, &cks,
    );
    assert_that_public_key_encryption_is_decrypted_by_client_key::<FheBool, bool>(true, &pks, &cks);
}

#[test]
fn test_integer_public_key() {
    let config = ConfigBuilder::default().build();

    let (cks, _sks) = generate_keys(config);

    let pks = PublicKey::new(&cks);

    assert_that_public_key_encryption_is_decrypted_by_client_key::<FheUint8, u8>(235, &pks, &cks);
}

#[test]
fn test_small_uint8() {
    let config = ConfigBuilder::default().build();

    let (cks, _sks) = generate_keys(config);

    let pks = PublicKey::new(&cks);

    assert_that_public_key_encryption_is_decrypted_by_client_key::<FheUint8, u8>(235, &pks, &cks);
}

#[test]
fn test_small_uint256() {
    let config = ConfigBuilder::default().build();

    let (cks, _sks) = generate_keys(config);

    let pks = PublicKey::new(&cks);

    use rand::prelude::*;
    let mut rng = rand::rng();
    let value = rng.gen::<U256>();
    assert_that_public_key_encryption_is_decrypted_by_client_key::<FheUint256, U256>(
        value, &pks, &cks,
    );
}

#[test]
fn test_server_key_decompression() -> Result<(), Box<dyn std::error::Error>> {
    use crate::set_server_key;

    let config = ConfigBuilder::default().build();

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
fn test_with_seed() {
    use crate::Seed;
    let builder = ConfigBuilder::default();
    let config = builder.build();

    let cks1 = ClientKey::generate_with_seed(config, Seed(125));
    let cks2 = ClientKey::generate(config);
    let cks3 = ClientKey::generate_with_seed(config, Seed(125));
    let cks4 = ClientKey::generate_with_seed(config, Seed(127));

    let cks1_serialized = bincode::serialize(&cks1).unwrap();
    let cks2_serialized = bincode::serialize(&cks2).unwrap();
    let cks3_serialized = bincode::serialize(&cks3).unwrap();
    let cks4_serialized = bincode::serialize(&cks4).unwrap();

    assert_eq!(&cks1_serialized, &cks3_serialized);
    assert_ne!(&cks1_serialized, &cks2_serialized);
    assert_ne!(&cks1_serialized, &cks4_serialized);
}

#[test]
fn test_with_context() {
    let config = ConfigBuilder::default().build();

    let (cks, sks) = generate_keys(config);

    let a = FheBool::encrypt(false, &cks);
    let b = FheBool::encrypt(true, &cks);

    let r = crate::high_level_api::with_server_key_as_context(sks, move || a & b);
    let d = r.decrypt(&cks);
    assert!(!d);
}

/// The purpose of this test is to assert that
/// the deserialize and serialize traits are implemented
#[test]
fn test_serialize_deserialize_are_implemented() {
    let config = ConfigBuilder::default().build();

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

#[test]
fn test_try_from_single_lwe_encryption_key() {
    let parameters = crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let lwe_sk = crate::shortint::engine::ShortintEngine::with_thread_local_mut(|engine| {
        crate::core_crypto::algorithms::allocate_and_generate_new_binary_lwe_secret_key(
            parameters
                .glwe_dimension
                .to_equivalent_lwe_dimension(parameters.polynomial_size),
            &mut engine.secret_generator,
        )
    });

    let shortint_key =
        crate::shortint::ClientKey::try_from_lwe_encryption_key(lwe_sk, parameters).unwrap();
    let client_key = ClientKey::from_raw_parts(
        shortint_key.into(),
        None,
        None,
        None,
        None,
        None,
        Tag::default(),
    );
    let sks = ServerKey::new(&client_key);

    let clear_a = 1344u32;
    let clear_b = 5u32;

    let encrypted_a = FheUint32::encrypt(clear_a, &client_key);
    let encrypted_b = FheUint32::encrypt(clear_b, &client_key);

    set_server_key(sks);

    let encrypted_res_mul = &encrypted_a + &encrypted_b;
    let clear_res: u32 = encrypted_res_mul.decrypt(&client_key);
    assert_eq!(clear_res, clear_a + clear_b);
}

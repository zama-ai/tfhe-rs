use rand::Rng;

use crate::high_level_api::prelude::*;
use crate::high_level_api::{generate_keys, set_server_key, ConfigBuilder, FheUint8};
use crate::integer::U256;
use crate::{
    CompactFheUint32, CompactFheUint32List, CompactPublicKey, CompressedFheUint16,
    CompressedFheUint256, CompressedPublicKey, Config, FheUint128, FheUint16, FheUint256,
    FheUint32, FheUint64,
};

#[test]
fn test_quickstart_uint8() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let clear_a = 27u8;
    let clear_b = 128u8;

    let a = FheUint8::encrypt(clear_a, &client_key);
    let b = FheUint8::encrypt(clear_b, &client_key);

    let result = a + b;

    let decrypted_result: u8 = result.decrypt(&client_key);

    let clear_result = clear_a + clear_b;

    assert_eq!(decrypted_result, clear_result);
}

#[test]
fn test_uint8_compare() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let clear_a = 27u8;
    let clear_b = 128u8;

    let a = FheUint8::encrypt(clear_a, &client_key);
    let b = FheUint8::encrypt(clear_b, &client_key);

    let result = &a.eq(&b);
    let decrypted_result: u8 = result.decrypt(&client_key);
    let clear_result = u8::from(clear_a == clear_b);
    assert_eq!(decrypted_result, clear_result);

    let result = &a.le(&b);
    let decrypted_result: u8 = result.decrypt(&client_key);
    let clear_result = u8::from(clear_a <= clear_b);
    assert_eq!(decrypted_result, clear_result);

    let result = &a.lt(&b);
    let decrypted_result: u8 = result.decrypt(&client_key);
    let clear_result = u8::from(clear_a < clear_b);
    assert_eq!(decrypted_result, clear_result);

    let result = &a.ge(&b);
    let decrypted_result: u8 = result.decrypt(&client_key);
    let clear_result = u8::from(clear_a >= clear_b);
    assert_eq!(decrypted_result, clear_result);

    let result = &a.gt(&b);
    let decrypted_result: u8 = result.decrypt(&client_key);
    let clear_result = u8::from(clear_a >= clear_b);
    assert_eq!(decrypted_result, clear_result);
}

#[test]
fn test_integer_compressed_can_be_serialized() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();
    let (client_key, _) = generate_keys(config);

    let clear = U256::from(u64::MAX);
    let compressed = CompressedFheUint256::try_encrypt(clear, &client_key).unwrap();

    let bytes = bincode::serialize(&compressed).unwrap();
    let deserialized: CompressedFheUint256 = bincode::deserialize_from(bytes.as_slice()).unwrap();

    let decompressed = FheUint256::from(deserialized);
    let clear_decompressed: U256 = decompressed.decrypt(&client_key);
    assert_eq!(clear_decompressed, clear);
}

#[test]
fn test_integer_compressed() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();
    let (client_key, _) = generate_keys(config);

    let clear = 12_837u16;
    let compressed = CompressedFheUint16::try_encrypt(clear, &client_key).unwrap();
    let decompressed = FheUint16::from(compressed);
    let clear_decompressed: u16 = decompressed.decrypt(&client_key);
    assert_eq!(clear_decompressed, clear);
}

#[test]
fn test_integer_compressed_small() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers_small()
        .build();
    let (client_key, _) = generate_keys(config);

    let clear = 12_837u16;
    let compressed = CompressedFheUint16::try_encrypt(clear, &client_key).unwrap();
    let decompressed = FheUint16::from(compressed);
    let clear_decompressed: u16 = decompressed.decrypt(&client_key);
    assert_eq!(clear_decompressed, clear);
}

#[test]
fn test_uint32() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();

    let (cks, sks) = generate_keys(config);

    use rand::prelude::*;

    let mut rng = rand::thread_rng();
    let clear_a = rng.gen::<u32>();
    let clear_b = rng.gen::<u32>();

    let a = FheUint32::try_encrypt(clear_a, &cks).unwrap();
    let b = FheUint32::try_encrypt(clear_b, &cks).unwrap();

    set_server_key(sks);

    let c = a + b;

    let decrypted: u32 = c.decrypt(&cks);
    assert_eq!(decrypted, clear_a.wrapping_add(clear_b));
}

#[test]
fn test_uint64() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();

    let (cks, sks) = generate_keys(config);

    use rand::prelude::*;

    let mut rng = rand::thread_rng();
    let clear_a = rng.gen::<u64>();
    let clear_b = rng.gen::<u64>();

    let a = FheUint64::try_encrypt(clear_a, &cks).unwrap();
    let b = FheUint64::try_encrypt(clear_b, &cks).unwrap();

    set_server_key(sks);

    let c = a + b;

    let decrypted: u64 = c.decrypt(&cks);
    assert_eq!(decrypted, clear_a.wrapping_add(clear_b));
}

#[test]
fn test_small_uint128() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers_small()
        .build();

    let (cks, sks) = generate_keys(config);

    use rand::prelude::*;

    let mut rng = rand::thread_rng();
    let clear_a = rng.gen::<u128>();
    let clear_b = rng.gen::<u128>();

    let a = FheUint128::try_encrypt(clear_a, &cks).unwrap();
    let b = FheUint128::try_encrypt(clear_b, &cks).unwrap();

    set_server_key(sks);

    let c = a + b;

    let decrypted: u128 = c.decrypt(&cks);
    assert_eq!(decrypted, clear_a.wrapping_add(clear_b));
}

#[test]
fn test_integer_compressed_public_key() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();
    let (client_key, _) = generate_keys(config);

    let public_key = CompressedPublicKey::new(&client_key);

    let a = FheUint8::try_encrypt(213u8, &public_key).unwrap();
    let clear: u8 = a.decrypt(&client_key);
    assert_eq!(clear, 213u8);
}

#[test]
fn test_decompressed_public_key_encrypt() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();
    let (client_key, _) = generate_keys(config);

    let compressed_public_key = CompressedPublicKey::new(&client_key);
    let public_key = compressed_public_key.decompress();

    let a = FheUint8::try_encrypt(255u8, &public_key).unwrap();
    let clear: u8 = a.decrypt(&client_key);
    assert_eq!(clear, 255u8);
}

#[test]
fn test_compact_public_key_big() {
    let config = ConfigBuilder::all_disabled()
        .enable_custom_integers(
            crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK,
            None,
        )
        .build();
    let (client_key, _) = generate_keys(config);

    let public_key = CompactPublicKey::new(&client_key);

    let a = FheUint8::try_encrypt(255u8, &public_key).unwrap();
    let clear: u8 = a.decrypt(&client_key);
    assert_eq!(clear, 255u8);
}

#[test]
fn test_compact_public_key_list_big() {
    let config = ConfigBuilder::all_disabled()
        .enable_custom_integers(
            crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_COMPACT_PK,
            None,
        )
        .build();
    test_compact_public_key_list(config);
}

#[test]
fn test_compact_public_key_list_small() {
    let config = ConfigBuilder::all_disabled()
        .enable_custom_integers(
            crate::shortint::parameters::PARAM_SMALL_MESSAGE_2_CARRY_2_COMPACT_PK,
            None,
        )
        .build();
    test_compact_public_key_list(config);
}

fn test_compact_public_key_list(config: Config) {
    let (client_key, server_key) = generate_keys(config);

    let public_key = CompactPublicKey::new(&client_key);

    let mut rng = rand::thread_rng();

    let clear_xs = (0..50).map(|_| rng.gen::<u32>()).collect::<Vec<_>>();
    let clear_ys = (0..50).map(|_| rng.gen::<u32>()).collect::<Vec<_>>();

    let compacted_xs = CompactFheUint32List::encrypt(&clear_xs, &public_key);
    let compacted_ys = CompactFheUint32List::encrypt(&clear_ys, &public_key);

    let exs = compacted_xs.expand();
    let eys = compacted_ys.expand();

    set_server_key(server_key);

    let encrypted_results = exs.iter().zip(eys).map(|(x, y)| x + y).collect::<Vec<_>>();
    let clear_results = clear_xs
        .iter()
        .zip(clear_ys)
        .map(|(x, y)| x + y)
        .collect::<Vec<_>>();

    for (encrypted, clear) in encrypted_results.iter().zip(clear_results) {
        let decrypted: u32 = encrypted.decrypt(&client_key);
        assert_eq!(clear, decrypted);
    }

    let compact_single = CompactFheUint32::encrypt(clear_xs[0], &public_key);
    let a = compact_single.expand();
    let decrypted: u32 = a.decrypt(&client_key);
    assert_eq!(clear_xs[0], decrypted);
}

#[test]
fn test_compact_public_key_small() {
    let config = ConfigBuilder::all_disabled()
        .enable_custom_integers(
            crate::shortint::parameters::PARAM_SMALL_MESSAGE_2_CARRY_2_COMPACT_PK,
            None,
        )
        .build();
    let (client_key, _) = generate_keys(config);

    let public_key = CompactPublicKey::new(&client_key);

    let a = FheUint8::try_encrypt(255u8, &public_key).unwrap();
    let clear: u8 = a.decrypt(&client_key);
    assert_eq!(clear, 255u8);
}

#[test]
fn test_trivial_fhe_uint8() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();
    let (client_key, sks) = generate_keys(config);

    set_server_key(sks);

    let a = FheUint8::try_encrypt_trivial(234u8).unwrap();

    let clear: u8 = a.decrypt(&client_key);
    assert_eq!(clear, 234);
}

#[test]
fn test_trivial_fhe_uint256_small() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers_small()
        .build();
    let (client_key, sks) = generate_keys(config);

    set_server_key(sks);

    let clear_a = U256::from(u128::MAX);
    let a = FheUint256::try_encrypt_trivial(clear_a).unwrap();
    let clear: U256 = a.decrypt(&client_key);
    assert_eq!(clear, clear_a);
}

#[test]
fn test_integer_casting() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();
    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    // Downcasting then Upcasting
    {
        let clear = 12_837u16;
        let a = FheUint16::encrypt(clear, &client_key);

        // Downcasting
        let a: FheUint8 = a.cast_into();
        let da: u8 = a.decrypt(&client_key);
        assert_eq!(da, clear as u8);

        // Upcasting
        let a: FheUint32 = a.cast_into();
        let da: u32 = a.decrypt(&client_key);
        assert_eq!(da, (clear as u8) as u32);
    }

    // Upcasting then Downcasting
    {
        let clear = 12_837u16;
        let a = FheUint16::encrypt(clear, &client_key);

        // Upcasting
        let a = FheUint32::cast_from(a);
        let da: u32 = a.decrypt(&client_key);
        assert_eq!(da, clear as u32);

        // Downcasting
        let a = FheUint8::cast_from(a);
        let da: u8 = a.decrypt(&client_key);
        assert_eq!(da, (clear as u32) as u8);
    }

    // Casting to self, it not useful but is supported
    {
        let clear = 43_129u16;
        let a = FheUint16::encrypt(clear, &client_key);
        let a = FheUint16::cast_from(a);
        let da: u16 = a.decrypt(&client_key);
        assert_eq!(da, clear);
    }
}

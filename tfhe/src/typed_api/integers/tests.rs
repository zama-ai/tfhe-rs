use crate::integer::U256;
use crate::typed_api::prelude::*;
use crate::typed_api::{generate_keys, set_server_key, ConfigBuilder, FheUint8};
use crate::{CompressedFheUint16, CompressedFheUint256, FheUint16, FheUint256};

#[test]
fn test_quickstart_uint8() {
    let config = ConfigBuilder::all_disabled().enable_default_uint8().build();

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
    let config = ConfigBuilder::all_disabled().enable_default_uint8().build();

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
        .enable_default_uint256()
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
        .enable_default_uint16()
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
        .enable_default_uint16_small()
        .build();
    let (client_key, _) = generate_keys(config);

    let clear = 12_837u16;
    let compressed = CompressedFheUint16::try_encrypt(clear, &client_key).unwrap();
    let decompressed = FheUint16::from(compressed);
    let clear_decompressed: u16 = decompressed.decrypt(&client_key);
    assert_eq!(clear_decompressed, clear);
}

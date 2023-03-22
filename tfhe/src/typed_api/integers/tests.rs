use crate::typed_api::prelude::*;
use crate::typed_api::{generate_keys, set_server_key, ConfigBuilder, FheUint8};

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

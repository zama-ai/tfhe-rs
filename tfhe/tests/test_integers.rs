#![cfg(feature = "integer")]

use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};

#[test]
fn test_uint8() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let a = FheUint8::encrypt(27u8, &client_key);
    let b = FheUint8::encrypt(100u8, &client_key);

    let c: u8 = (a + b).decrypt(&client_key);
    assert_eq!(c, 127);
}

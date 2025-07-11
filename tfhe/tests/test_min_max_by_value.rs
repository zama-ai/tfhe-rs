use rand::Rng;
use tfhe::prelude::{FheEncrypt, FheDecrypt, FheMin, FheMax};
use tfhe::{FheUint8, generate_keys, set_server_key, ConfigBuilder};

#[test]
fn test_min_max_by_value_and_reference() {
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key);

    let mut rng = rand::thread_rng();
    let a_val: u8 = rng.gen();
    let b_val: u8 = rng.gen();

    let a = FheUint8::encrypt(a_val, &client_key);
    let b = FheUint8::encrypt(b_val, &client_key);

    // Test by-value operations
    let min_by_value = a.min(b.clone());
    let max_by_value = a.max(b.clone());
    let min_result: u8 = min_by_value.decrypt(&client_key);
    let max_result: u8 = max_by_value.decrypt(&client_key);
    assert_eq!(min_result, a_val.min(b_val));
    assert_eq!(max_result, a_val.max(b_val));

    // Test by-reference operations
    let a_ref = FheUint8::encrypt(a_val, &client_key);
    let b_ref = FheUint8::encrypt(b_val, &client_key);
    let min_by_ref = a_ref.min(&b_ref);
    let max_by_ref = a_ref.max(&b_ref);
    let min_ref_result: u8 = min_by_ref.decrypt(&client_key);
    let max_ref_result: u8 = max_by_ref.decrypt(&client_key);
    assert_eq!(min_ref_result, a_val.min(b_val));
    assert_eq!(max_ref_result, a_val.max(b_val));
} 
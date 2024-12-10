use crate::boolean::keycache::KEY_CACHE;
use crate::boolean::prelude::*;

#[test]
fn test_cast_boolean() {
    let keys_1 = KEY_CACHE.get_from_param(DEFAULT_PARAMETERS);
    let client_key_1 = keys_1.client_key();
    let keys_2 = KEY_CACHE.get_from_param(DEFAULT_PARAMETERS);
    let client_key_2 = keys_2.client_key();

    let ksk_params = BooleanKeySwitchingParameters::new(
        client_key_2.parameters.ks_base_log,
        client_key_2.parameters.ks_level,
    );
    let ksk = KeySwitchingKey::new(client_key_1, client_key_2, ksk_params);

    let mut ct_true = client_key_1.encrypt(true);
    ct_true = ksk.cast(&ct_true);
    let clear = client_key_2.decrypt(&ct_true);
    assert!(clear);

    let mut ct_false = client_key_1.encrypt(false);
    ct_false = ksk.cast(&ct_false);
    let clear = client_key_2.decrypt(&ct_false);
    assert!(!clear);
}

#[test]
fn test_cast_into_boolean() {
    let keys_1 = KEY_CACHE.get_from_param(DEFAULT_PARAMETERS);
    let (client_key_1, server_key_1) = (keys_1.client_key(), keys_1.server_key());
    let keys_2 = KEY_CACHE.get_from_param(DEFAULT_PARAMETERS);
    let client_key_2 = keys_2.client_key();

    let ksk_params = BooleanKeySwitchingParameters::new(
        client_key_2.parameters.ks_base_log,
        client_key_2.parameters.ks_level,
    );
    let ksk = KeySwitchingKey::new(client_key_1, client_key_2, ksk_params);

    let ct_true = client_key_1.encrypt(true);
    let mut ct_cast = server_key_1.trivial_encrypt(false);
    ksk.cast_into(&ct_true, &mut ct_cast);
    let clear = client_key_2.decrypt(&ct_cast);
    assert!(clear);

    let ct_false = client_key_1.encrypt(false);
    let mut ct_cast = server_key_1.trivial_encrypt(true);
    ksk.cast_into(&ct_false, &mut ct_cast);
    let clear = client_key_2.decrypt(&ct_cast);
    assert!(!clear);
}

use crate::boolean::prelude::*;

#[test]
fn test_cast_boolean() {
    let (client_key_1, _server_key_1): (ClientKey, ServerKey) = gen_keys();
    let (client_key_2, _server_key_2): (ClientKey, ServerKey) = gen_keys();

    let ksk = CastingKey::new(&client_key_1, &client_key_2);

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
fn test_castassign_boolean() {
    let (client_key_1, server_key_1): (ClientKey, ServerKey) = gen_keys();
    let (client_key_2, _server_key_2): (ClientKey, ServerKey) = gen_keys();

    let ksk = CastingKey::new(&client_key_1, &client_key_2);

    let ct_true = client_key_1.encrypt(true);
    let mut ct_cast = server_key_1.trivial_encrypt(false);
    ksk.cast_assign(&ct_true, &mut ct_cast);
    let clear = client_key_2.decrypt(&ct_cast);
    assert!(clear);

    let ct_false = client_key_1.encrypt(false);
    let mut ct_cast = server_key_1.trivial_encrypt(true);
    ksk.cast_assign(&ct_false, &mut ct_cast);
    let clear = client_key_2.decrypt(&ct_cast);
    assert!(!clear);
}

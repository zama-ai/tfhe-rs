const crypto = require('crypto');
const test = require('node:test');
const assert = require('node:assert').strict;
const { Boolean, Shortint, BooleanParameterSet } = require("../pkg");

function genRandomBigIntWithBytes(byteCount) {
    return BigInt('0x' + crypto.randomBytes(byteCount).toString('hex'))
}

// Boolean tests
test('boolean_encrypt_decrypt', (t) => {
    let params = Boolean.get_boolean_parameters(BooleanParameterSet.Default);
    let cks = Boolean.new_client_key(params);
    let ct = Boolean.encrypt(cks, true);

    let serialized_cks = Boolean.serialize_boolean_client_key(cks);
    let deserialized_cks = Boolean.deserialize_boolean_client_key(serialized_cks);

    let serialized_ct = Boolean.serialize_boolean_ciphertext(ct);
    let deserialized_ct = Boolean.deserialize_boolean_ciphertext(serialized_ct);

    let decrypted = Boolean.decrypt(deserialized_cks, deserialized_ct);
    assert.deepEqual(decrypted, true);
});

test('boolean_public_encrypt_decrypt', (t) => {
    let params = Boolean.get_boolean_parameters(BooleanParameterSet.Default);
    let cks = Boolean.new_client_key(params);
    let pk = Boolean.new_public_key(cks);

    let serialized_pk = Boolean.serialize_boolean_public_key(pk);
    let deserialized_pk = Boolean.deserialize_boolean_public_key(serialized_pk);

    let ct = Boolean.encrypt_with_public_key(deserialized_pk, true);

    let serialized_ct = Boolean.serialize_boolean_ciphertext(ct);
    let deserialized_ct = Boolean.deserialize_boolean_ciphertext(serialized_ct);

    let decrypted = Boolean.decrypt(cks, deserialized_ct);
    assert.deepEqual(decrypted, true);
});

test('boolean_deterministic_keygen', (t) => {
    const TEST_LOOP_COUNT = 128;

    let seed_high_bytes = genRandomBigIntWithBytes(8);
    let seed_low_bytes = genRandomBigIntWithBytes(8);

    let params = Boolean.get_boolean_parameters(BooleanParameterSet.Default);
    let cks = Boolean.new_client_key_from_seed_and_parameters(seed_high_bytes, seed_low_bytes, params);
    let other_cks = Boolean.new_client_key_from_seed_and_parameters(seed_high_bytes, seed_low_bytes, params);

    for (let i = 0; i < TEST_LOOP_COUNT; i++) {
        let ct_true = Boolean.encrypt(cks, true);
        let decrypt_true_other = Boolean.decrypt(other_cks, ct_true);
        assert.deepEqual(decrypt_true_other, true);

        let ct_false = Boolean.encrypt(cks, false);
        let decrypt_false_other = Boolean.decrypt(other_cks, ct_false);
        assert.deepEqual(decrypt_false_other, false);
    }
});


// Shortint tests
test('shortint_encrypt_decrypt', (t) => {
    let params = Shortint.get_shortint_parameters(2, 2);
    let cks = Shortint.new_client_key(params);
    let ct = Shortint.encrypt(cks, BigInt(3));

    let serialized_cks = Shortint.serialize_shortint_client_key(cks);
    let deserialized_cks = Shortint.deserialize_shortint_client_key(serialized_cks);

    let serialized_ct = Shortint.serialize_shortint_ciphertext(ct);
    let deserialized_ct = Shortint.deserialize_shortint_ciphertext(serialized_ct);

    let decrypted = Shortint.decrypt(deserialized_cks, deserialized_ct);
    assert.deepEqual(decrypted, BigInt(3));
});

test('shortint_public_encrypt_decrypt', (t) => {
    let params = Shortint.get_shortint_parameters(2, 0);
    let cks = Shortint.new_client_key(params);
    let pk = Shortint.new_public_key(cks);

    let ct = Shortint.encrypt_with_public_key(pk, BigInt(3));

    let serialized_ct = Shortint.serialize_shortint_ciphertext(ct);
    let deserialized_ct = Shortint.deserialize_shortint_ciphertext(serialized_ct);

    let decrypted = Shortint.decrypt(cks, deserialized_ct);
    assert.deepEqual(decrypted, BigInt(3));
});

test('shortint_deterministic_keygen', (t) => {
    const TEST_LOOP_COUNT = 128;

    let seed_high_bytes = genRandomBigIntWithBytes(8);
    let seed_low_bytes = genRandomBigIntWithBytes(8);

    let params = Shortint.get_shortint_parameters(2, 2);
    let cks = Shortint.new_client_key_from_seed_and_parameters(seed_high_bytes, seed_low_bytes, params);
    let other_cks = Shortint.new_client_key_from_seed_and_parameters(seed_high_bytes, seed_low_bytes, params);

    for (let i = 0; i < TEST_LOOP_COUNT; i++) {
        let random_message = genRandomBigIntWithBytes(4) % BigInt(4);
        let ct = Shortint.encrypt(cks, random_message);
        let decrypt_other = Shortint.decrypt(other_cks, ct);
        assert.deepEqual(decrypt_other, random_message);
    }
});
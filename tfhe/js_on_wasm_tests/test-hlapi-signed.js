const test = require('node:test');
const assert = require('node:assert').strict;
const { performance } = require('perf_hooks');
const {
    init_panic_hook,
    ShortintParametersName,
    ShortintParameters,
    TfheClientKey,
    TfhePublicKey,
    TfheCompressedPublicKey,
    TfheCompactPublicKey,
    TfheCompressedServerKey,
    TfheConfigBuilder,
    CompressedFheInt8,
    FheInt8,
    FheInt32,
    CompactFheInt32,
    CompactFheInt32List,
    CompressedFheInt128,
    FheInt128,
    CompressedFheInt256,
    CompactFheInt256,
    CompactFheInt256List,
    FheInt256
} = require("../pkg/tfhe.js");


const I256_MIN = BigInt("-57896044618658097711785492504343953926634992332820282019728792003956564819968");
const I256_MAX = BigInt("28948022309329048855892746252171976963317496166410141009864396001978282409983");
const I128_MIN = BigInt("-170141183460469231731687303715884105728");
const I32_MIN = -2147483648;

// This is useful to debug test
init_panic_hook();


test('hlapi_client_key_encrypt_decrypt_int8_big', (t) => {
    let config = TfheConfigBuilder.default()
        .build();

    let clientKey = TfheClientKey.generate(config);

    let clear = -73;
    let encrypted = FheInt8.encrypt_with_client_key(clear, clientKey);
    let decrypted = encrypted.decrypt(clientKey);
    assert.deepStrictEqual(decrypted, clear);

    let serialized = encrypted.serialize();
    let deserialized = FheInt8.deserialize(serialized);
    let deserialized_decrypted = deserialized.decrypt(clientKey);
    assert.deepStrictEqual(deserialized_decrypted, clear);

    let safe_serialized = encrypted.safe_serialize(BigInt(10000000));
    let safe_deserialized = FheInt8.safe_deserialize(safe_serialized, BigInt(10000000));
    let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
    assert.deepStrictEqual(safe_deserialized_decrypted, clear);
});

test('hlapi_compressed_public_client_int8_big', (t) => {
    let config = TfheConfigBuilder.default()
        .build();

    let clientKey = TfheClientKey.generate(config);

    let clear = -128;
    let compressed_encrypted = CompressedFheInt8.encrypt_with_client_key(clear, clientKey);
    let compressed_serialized = compressed_encrypted.serialize();
    let compressed_deserialized = CompressedFheInt8.deserialize(compressed_serialized);
    let decompressed = compressed_deserialized.decompress()

    let decrypted = decompressed.decrypt(clientKey);
    assert.deepStrictEqual(decrypted, clear);

    let compressed_safe_serialized = compressed_encrypted.safe_serialize(BigInt(10000000));
    let compressed_safe_deserialized = CompressedFheInt8.safe_deserialize(compressed_safe_serialized, BigInt(10000000));
    let safe_decompressed = compressed_safe_deserialized.decompress()

    let safe_decrypted = safe_decompressed.decrypt(clientKey);
    assert.deepStrictEqual(safe_decrypted, clear);
});

test('hlapi_public_key_encrypt_decrypt_int32_small', (t) => {
    let config = TfheConfigBuilder.default_with_small_encryption()
        .build();

    let clientKey = TfheClientKey.generate(config);
    let publicKey = TfhePublicKey.new(clientKey);

    let encrypted = FheInt32.encrypt_with_public_key(I32_MIN, publicKey);
    let decrypted = encrypted.decrypt(clientKey);
    assert.deepStrictEqual(decrypted, I32_MIN);

    let serialized = encrypted.serialize();
    let deserialized = FheInt32.deserialize(serialized);
    let deserialized_decrypted = deserialized.decrypt(clientKey);
    assert.deepStrictEqual(deserialized_decrypted, I32_MIN);

    let safe_serialized = encrypted.safe_serialize(BigInt(1000000));
    let safe_deserialized = FheInt32.safe_deserialize(safe_serialized, BigInt(1000000));
    let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
    assert.deepStrictEqual(safe_deserialized_decrypted, I32_MIN);
});

test('hlapi_decompress_public_key_then_encrypt_decrypt_int32_small', (t) => {
    let config = TfheConfigBuilder.default_with_small_encryption()
        .build();


    let clientKey = TfheClientKey.generate(config);
    var startTime = performance.now()
    let compressedPublicKey = TfheCompressedPublicKey.new(clientKey);
    var endTime = performance.now()

    let data = compressedPublicKey.serialize()

    let publicKey = compressedPublicKey.decompress();


    var startTime = performance.now()
    let encrypted = FheInt32.encrypt_with_public_key(I32_MIN, publicKey);
    var endTime = performance.now()

    let ser = encrypted.serialize();
    let decrypted = encrypted.decrypt(clientKey);
    assert.deepStrictEqual(decrypted, I32_MIN);

    let serialized = encrypted.serialize();
    let deserialized = FheInt32.deserialize(serialized);
    let deserialized_decrypted = deserialized.decrypt(clientKey);
    assert.deepStrictEqual(deserialized_decrypted, I32_MIN);

    let safe_serialized = encrypted.safe_serialize(BigInt(10000000));
    let safe_deserialized = FheInt32.safe_deserialize(safe_serialized, BigInt(10000000));
    let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
    assert.deepStrictEqual(safe_deserialized_decrypted, I32_MIN);
});

test('hlapi_client_key_encrypt_decrypt_int128_big', (t) => {
    let config = TfheConfigBuilder.default()
        .build();

    let clientKey = TfheClientKey.generate(config);

    let encrypted = FheInt128.encrypt_with_client_key(I128_MIN, clientKey);
    let decrypted = encrypted.decrypt(clientKey);
    assert.deepStrictEqual(decrypted, I128_MIN);

    let serialized = encrypted.serialize();
    let deserialized = FheInt128.deserialize(serialized);
    let deserialized_decrypted = deserialized.decrypt(clientKey);
    assert.deepStrictEqual(deserialized_decrypted, I128_MIN);

    let safe_serialized = encrypted.safe_serialize(BigInt(10000000));
    let safe_deserialized = FheInt128.safe_deserialize(safe_serialized, BigInt(10000000));
    let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
    assert.deepStrictEqual(safe_deserialized_decrypted, I128_MIN);

    // Compressed
    let compressed_encrypted = CompressedFheInt128.encrypt_with_client_key(I128_MIN, clientKey);
    let compressed_serialized = compressed_encrypted.serialize();
    let compressed_deserialized = CompressedFheInt128.deserialize(compressed_serialized);
    let decompressed = compressed_deserialized.decompress()

    decrypted = decompressed.decrypt(clientKey);
    assert.deepStrictEqual(decrypted, I128_MIN);

    let compressed_safe_serialized = compressed_encrypted.safe_serialize(BigInt(10000000));
    let compressed_safe_deserialized = CompressedFheInt128.safe_deserialize(compressed_safe_serialized, BigInt(10000000));
    let safe_decompressed = compressed_safe_deserialized.decompress()

    safe_decrypted = safe_decompressed.decrypt(clientKey);
    assert.deepStrictEqual(safe_decrypted, I128_MIN);
});

test('hlapi_client_key_encrypt_decrypt_int128_small', (t) => {
    let config = TfheConfigBuilder.default_with_small_encryption()
        .build();

    let clientKey = TfheClientKey.generate(config);

    let encrypted = FheInt128.encrypt_with_client_key(I128_MIN, clientKey);
    let decrypted = encrypted.decrypt(clientKey);
    assert.deepStrictEqual(decrypted, I128_MIN);

    let serialized = encrypted.serialize();
    let deserialized = FheInt128.deserialize(serialized);
    let deserialized_decrypted = deserialized.decrypt(clientKey);
    assert.deepStrictEqual(deserialized_decrypted, I128_MIN);

    let safe_serialized = encrypted.safe_serialize(BigInt(10000000));
    let safe_deserialized = FheInt128.safe_deserialize(safe_serialized, BigInt(10000000));
    let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
    assert.deepStrictEqual(safe_deserialized_decrypted, I128_MIN);

    // Compressed
    let compressed_encrypted = CompressedFheInt128.encrypt_with_client_key(I128_MIN, clientKey);
    let compressed_serialized = compressed_encrypted.serialize();
    let compressed_deserialized = CompressedFheInt128.deserialize(compressed_serialized);
    let decompressed = compressed_deserialized.decompress()

    decrypted = decompressed.decrypt(clientKey);
    assert.deepStrictEqual(decrypted, I128_MIN);

    let compressed_safe_serialized = compressed_encrypted.safe_serialize(BigInt(10000000));
    let compressed_safe_deserialized = CompressedFheInt128.safe_deserialize(compressed_safe_serialized, BigInt(10000000));
    let safe_decompressed = compressed_safe_deserialized.decompress()

    safe_decrypted = safe_decompressed.decrypt(clientKey);
    assert.deepStrictEqual(safe_decrypted, I128_MIN);
});

test('hlapi_client_key_encrypt_decrypt_int256_big', (t) => {
    let config = TfheConfigBuilder.default()
        .build();


    let clientKey = TfheClientKey.generate(config);


    let round_trip_encrypt = (value) => {
        let encrypted = FheInt256.encrypt_with_client_key(value, clientKey);
        let decrypted = encrypted.decrypt(clientKey);
        assert.deepStrictEqual(decrypted, value);

        let serialized = encrypted.serialize();
        let deserialized = FheInt256.deserialize(serialized);
        let deserialized_decrypted = deserialized.decrypt(clientKey);
        assert.deepStrictEqual(deserialized_decrypted, value);

        let safe_serialized = encrypted.safe_serialize(BigInt(10000000));
        let safe_deserialized = FheInt256.safe_deserialize(safe_serialized, BigInt(10000000));
        let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
        assert.deepStrictEqual(safe_deserialized_decrypted, value);

        // Compressed
        let compressed_encrypted = CompressedFheInt256.encrypt_with_client_key(value, clientKey);
        let compressed_serialized = compressed_encrypted.serialize();
        let compressed_deserialized = CompressedFheInt256.deserialize(compressed_serialized);
        let decompressed = compressed_deserialized.decompress();

        decrypted = decompressed.decrypt(clientKey);
        assert.deepStrictEqual(decrypted, value);

        let compressed_safe_serialized = compressed_encrypted.safe_serialize(BigInt(10000000));
        let compressed_safe_deserialized = CompressedFheInt256.safe_deserialize(compressed_safe_serialized, BigInt(10000000));
        let safe_decompressed = compressed_safe_deserialized.decompress()

        safe_decrypted = safe_decompressed.decrypt(clientKey);
        assert.deepStrictEqual(safe_decrypted, value);
    };


    round_trip_encrypt(I256_MIN);
    round_trip_encrypt(I256_MAX);
    round_trip_encrypt(BigInt(-1));
    round_trip_encrypt(BigInt(1));
    round_trip_encrypt(BigInt(-128));
    round_trip_encrypt(BigInt(128));
});

test('hlapi_client_key_encrypt_decrypt_int256_small', (t) => {
    let config = TfheConfigBuilder.default_with_small_encryption()
        .build();


    let clientKey = TfheClientKey.generate(config);

    let round_trip_encrypt = (value) => {
        let encrypted = FheInt256.encrypt_with_client_key(value, clientKey);
        let decrypted = encrypted.decrypt(clientKey);
        assert.deepStrictEqual(decrypted, value);

        let serialized = encrypted.serialize();
        let deserialized = FheInt256.deserialize(serialized);
        let deserialized_decrypted = deserialized.decrypt(clientKey);
        assert.deepStrictEqual(deserialized_decrypted, value);

        let safe_serialized = encrypted.safe_serialize(BigInt(10000000));
        let safe_deserialized = FheInt256.safe_deserialize(safe_serialized, BigInt(10000000));
        let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
        assert.deepStrictEqual(safe_deserialized_decrypted, value);

        // Compressed
        let compressed_encrypted = CompressedFheInt256.encrypt_with_client_key(value, clientKey);
        let compressed_serialized = compressed_encrypted.serialize();
        let compressed_deserialized = CompressedFheInt256.deserialize(compressed_serialized);
        let decompressed = compressed_deserialized.decompress()

        decrypted = decompressed.decrypt(clientKey);
        assert.deepStrictEqual(decrypted, value);

        let compressed_safe_serialized = compressed_encrypted.safe_serialize(BigInt(10000000));
        let compressed_safe_deserialized = CompressedFheInt256.safe_deserialize(compressed_safe_serialized, BigInt(10000000));
        let safe_decompressed = compressed_safe_deserialized.decompress()

        safe_decrypted = safe_decompressed.decrypt(clientKey);
        assert.deepStrictEqual(safe_decrypted, value);
    }

    round_trip_encrypt(I256_MIN);
    round_trip_encrypt(I256_MAX);
    round_trip_encrypt(BigInt(-1));
    round_trip_encrypt(BigInt(1));
    round_trip_encrypt(BigInt(-128));
    round_trip_encrypt(BigInt(128));
});

test('hlapi_decompress_public_key_then_encrypt_decrypt_int256_small', (t) => {
    let config = TfheConfigBuilder.default_with_small_encryption()
        .build();


    let clientKey = TfheClientKey.generate(config);
    let compressedPublicKey = TfheCompressedPublicKey.new(clientKey);
    let publicKey = compressedPublicKey.decompress();


    let encrypted = FheInt256.encrypt_with_public_key(I256_MIN, publicKey);
    let decrypted = encrypted.decrypt(clientKey);
    assert.deepStrictEqual(decrypted, I256_MIN);

    let serialized = encrypted.serialize();
    let deserialized = FheInt256.deserialize(serialized);
    let deserialized_decrypted = deserialized.decrypt(clientKey);
    assert.deepStrictEqual(deserialized_decrypted, I256_MIN);

    let safe_serialized = encrypted.safe_serialize(BigInt(10000000));
    let safe_deserialized = FheInt256.safe_deserialize(safe_serialized, BigInt(10000000));
    let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
    assert.deepStrictEqual(safe_deserialized_decrypted, I256_MIN);
});

test('hlapi_public_key_encrypt_decrypt_int256_small', (t) => {
    let config = TfheConfigBuilder.default_with_small_encryption().build();

    let clientKey = TfheClientKey.generate(config);
    let publicKey = TfhePublicKey.new(clientKey);

    let encrypted = FheInt256.encrypt_with_public_key(I256_MIN, publicKey);
    let decrypted = encrypted.decrypt(clientKey);
    assert.deepStrictEqual(decrypted, I256_MIN);

    let serialized = encrypted.serialize();
    let deserialized = FheInt256.deserialize(serialized);
    let deserialized_decrypted = deserialized.decrypt(clientKey);
    assert.deepStrictEqual(deserialized_decrypted, I256_MIN);

    let safe_serialized = encrypted.safe_serialize(BigInt(10000000));
    let safe_deserialized = FheInt256.safe_deserialize(safe_serialized, BigInt(10000000));
    let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
    assert.deepStrictEqual(safe_deserialized_decrypted, I256_MIN);
});



//////////////////////////////////////////////////////////////////////////////
/// 32 bits compact
//////////////////////////////////////////////////////////////////////////////

function hlapi_compact_public_key_encrypt_decrypt_int32_single(config) {
    let clientKey = TfheClientKey.generate(config);
    let publicKey = TfheCompactPublicKey.new(clientKey);

    let encrypted = FheInt32.encrypt_with_compact_public_key(I32_MIN, publicKey);
    let decrypted = encrypted.decrypt(clientKey);
    assert.deepStrictEqual(decrypted, I32_MIN);

    let serialized = encrypted.serialize();
    let deserialized = FheInt32.deserialize(serialized);
    let deserialized_decrypted = deserialized.decrypt(clientKey);
    assert.deepStrictEqual(deserialized_decrypted, I32_MIN);

    let safe_serialized = encrypted.safe_serialize(BigInt(10000000));
    let safe_deserialized = FheInt32.safe_deserialize(safe_serialized, BigInt(10000000));
    let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
    assert.deepStrictEqual(safe_deserialized_decrypted, I32_MIN);
}

test('hlapi_compact_public_key_encrypt_decrypt_int32_big_single', (t) => {
    const block_params = new ShortintParameters(ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS);
    let config = TfheConfigBuilder.default()
        .use_custom_parameters(block_params)
        .build();

    hlapi_compact_public_key_encrypt_decrypt_int32_single(config);
});

test('hlapi_compact_public_key_encrypt_decrypt_int32_small_single', (t) => {
    const block_params = new ShortintParameters(ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS);
    let config = TfheConfigBuilder.default()
        .use_custom_parameters(block_params)
        .build();

    hlapi_compact_public_key_encrypt_decrypt_int32_single(config);
});

function hlapi_compact_public_key_encrypt_decrypt_int32_single_compact(config) {
    let clientKey = TfheClientKey.generate(config);
    let publicKey = TfheCompactPublicKey.new(clientKey);

    let compact_encrypted = CompactFheInt32.encrypt_with_compact_public_key(I32_MIN, publicKey);
    let encrypted = compact_encrypted.expand();
    let decrypted = encrypted.decrypt(clientKey);
    assert.deepStrictEqual(decrypted, I32_MIN);

    let serialized = compact_encrypted.serialize();
    let deserialized = CompactFheInt32.deserialize(serialized);
    let deserialized_decrypted = deserialized.expand().decrypt(clientKey);
    assert.deepStrictEqual(deserialized_decrypted, I32_MIN);

    let safe_serialized = compact_encrypted.safe_serialize(BigInt(10000000));
    let safe_deserialized = CompactFheInt32.safe_deserialize(safe_serialized, BigInt(10000000));
    let safe_deserialized_decrypted = safe_deserialized.expand().decrypt(clientKey);
    assert.deepStrictEqual(safe_deserialized_decrypted, I32_MIN);
}

test('hlapi_compact_public_key_encrypt_decrypt_int32_small_single_compact', (t) => {
    const block_params = new ShortintParameters(ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS);
    let config = TfheConfigBuilder.default()
        .use_custom_parameters(block_params)
        .build();

    hlapi_compact_public_key_encrypt_decrypt_int32_single_compact(config);
});

test('hlapi_compact_public_key_encrypt_decrypt_int32_big_single_compact', (t) => {
    const block_params = new ShortintParameters(ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS);
    let config = TfheConfigBuilder.default()
        .use_custom_parameters(block_params)
        .build();

    hlapi_compact_public_key_encrypt_decrypt_int32_single_compact(config);
});

function hlapi_compact_public_key_encrypt_decrypt_int32_list_compact(config) {
    let clientKey = TfheClientKey.generate(config);
    let publicKey = TfheCompactPublicKey.new(clientKey);

    let values = [0, 1, 2394, I32_MIN];

    let compact_list = CompactFheInt32List.encrypt_with_compact_public_key(values, publicKey);

    {
        let encrypted_list = compact_list.expand();

        assert.deepStrictEqual(encrypted_list.length, values.length);

        for (let i = 0; i < values.length; i++) {
            let decrypted = encrypted_list[i].decrypt(clientKey);
            assert.deepStrictEqual(decrypted, values[i]);
        }
    }

    let serialized_list = compact_list.serialize();
    let deserialized_list = CompactFheInt32List.deserialize(serialized_list);
    let encrypted_list = deserialized_list.expand();
    assert.deepStrictEqual(encrypted_list.length, values.length);

    for (let i = 0; i < values.length; i++) {
        let decrypted = encrypted_list[i].decrypt(clientKey);
        assert.deepStrictEqual(decrypted, values[i]);
    }
}

test('hlapi_compact_public_key_encrypt_decrypt_int32_small_list_compact', (t) => {
    const block_params = new ShortintParameters(ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS);
    let config = TfheConfigBuilder.default()
        .use_custom_parameters(block_params)
        .build();

    hlapi_compact_public_key_encrypt_decrypt_int32_list_compact(config);
});

test('hlapi_compact_public_key_encrypt_decrypt_int32_big_list_compact', (t) => {
    const block_params = new ShortintParameters(ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS);
    let config = TfheConfigBuilder.default()
        .use_custom_parameters(block_params)
        .build();

    hlapi_compact_public_key_encrypt_decrypt_int32_list_compact(config);
});


//////////////////////////////////////////////////////////////////////////////
/// 256 bits compact
//////////////////////////////////////////////////////////////////////////////

function hlapi_compact_public_key_encrypt_decrypt_int256_single(config) {
    let clientKey = TfheClientKey.generate(config);
    let publicKey = TfheCompactPublicKey.new(clientKey);

    let encrypted = FheInt256.encrypt_with_compact_public_key(I256_MIN, publicKey);
    let decrypted = encrypted.decrypt(clientKey);
    assert.deepStrictEqual(decrypted, I256_MIN);

    let serialized = encrypted.serialize();
    let deserialized = FheInt256.deserialize(serialized);
    let deserialized_decrypted = deserialized.decrypt(clientKey);
    assert.deepStrictEqual(deserialized_decrypted, I256_MIN);

    let safe_serialized = encrypted.safe_serialize(BigInt(10000000));
    let safe_deserialized = FheInt256.safe_deserialize(safe_serialized, BigInt(10000000));
    let safe_deserialized_decrypted = safe_deserialized.decrypt(clientKey);
    assert.deepStrictEqual(safe_deserialized_decrypted, I256_MIN);
}

test('hlapi_compact_public_key_encrypt_decrypt_int256_big_single', (t) => {
    const block_params = new ShortintParameters(ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS);
    let config = TfheConfigBuilder.default()
        .use_custom_parameters(block_params)
        .build();

    hlapi_compact_public_key_encrypt_decrypt_int256_single(config);
});

test('hlapi_compact_public_key_encrypt_decrypt_int256_small_single', (t) => {
    const block_params = new ShortintParameters(ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS);
    let config = TfheConfigBuilder.default()
        .use_custom_parameters(block_params)
        .build();

    hlapi_compact_public_key_encrypt_decrypt_int256_single(config);
});

function hlapi_compact_public_key_encrypt_decrypt_int256_single_compact(config) {
    let clientKey = TfheClientKey.generate(config);
    let publicKey = TfheCompactPublicKey.new(clientKey);

    let compact_encrypted = CompactFheInt256.encrypt_with_compact_public_key(I256_MIN, publicKey);
    let encrypted = compact_encrypted.expand();
    let decrypted = encrypted.decrypt(clientKey);
    assert.deepStrictEqual(decrypted, I256_MIN);

    let serialized = compact_encrypted.serialize();
    let deserialized = CompactFheInt256.deserialize(serialized);
    let deserialized_decrypted = deserialized.expand().decrypt(clientKey);
    assert.deepStrictEqual(deserialized_decrypted, I256_MIN);

    let safe_serialized = compact_encrypted.safe_serialize(BigInt(10000000));
    let safe_deserialized = CompactFheInt256.safe_deserialize(safe_serialized, BigInt(10000000));
    let safe_deserialized_decrypted = safe_deserialized.expand().decrypt(clientKey);
    assert.deepStrictEqual(safe_deserialized_decrypted, I256_MIN);
}

test('hlapi_compact_public_key_encrypt_decrypt_int256_small_single_compact', (t) => {
    const block_params = new ShortintParameters(ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS);
    let config = TfheConfigBuilder.default()
        .use_custom_parameters(block_params)
        .build();

    hlapi_compact_public_key_encrypt_decrypt_int256_single_compact(config);
});

test('hlapi_compact_public_key_encrypt_decrypt_int256_big_single_compact', (t) => {
    const block_params = new ShortintParameters(ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS);
    let config = TfheConfigBuilder.default()
        .use_custom_parameters(block_params)
        .build();

    hlapi_compact_public_key_encrypt_decrypt_int256_single_compact(config);
});

function hlapi_compact_public_key_encrypt_decrypt_int256_list_compact(config) {
    let clientKey = TfheClientKey.generate(config);
    let publicKey = TfheCompactPublicKey.new(clientKey);

    let values = [BigInt(0), BigInt(1), BigInt(2394), BigInt(-2309840239), BigInt(I32_MIN), I256_MIN, I128_MIN];

    let compact_list = CompactFheInt256List.encrypt_with_compact_public_key(values, publicKey);

    {
        let encrypted_list = compact_list.expand();

        assert.deepStrictEqual(encrypted_list.length, values.length);

        for (let i = 0; i < values.length; i++) {
            let decrypted = encrypted_list[i].decrypt(clientKey);
            assert.deepStrictEqual(decrypted, values[i]);
        }
    }

    let serialized_list = compact_list.serialize();
    let deserialized_list = CompactFheInt256List.deserialize(serialized_list);
    let encrypted_list = deserialized_list.expand();
    assert.deepStrictEqual(encrypted_list.length, values.length);

    for (let i = 0; i < values.length; i++) {
        let decrypted = encrypted_list[i].decrypt(clientKey);
        assert.deepStrictEqual(decrypted, values[i]);
    }
}

test('hlapi_compact_public_key_encrypt_decrypt_int256_small_list_compact', (t) => {
    const block_params = new ShortintParameters(ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS);
    let config = TfheConfigBuilder.default()
        .use_custom_parameters(block_params)
        .build();

    hlapi_compact_public_key_encrypt_decrypt_int256_list_compact(config);
});

test('hlapi_compact_public_key_encrypt_decrypt_int256_big_list_compact', (t) => {
    const block_params = new ShortintParameters(ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS);
    let config = TfheConfigBuilder.default()
        .use_custom_parameters(block_params)
        .build();

    hlapi_compact_public_key_encrypt_decrypt_int256_list_compact(config);
});

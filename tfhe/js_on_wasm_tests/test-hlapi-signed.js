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
    TfheConfigBuilder,
    CompressedFheInt8,
    FheInt8,
    FheInt32,
    CompressedFheInt128,
    FheInt128,
    CompressedFheInt256,
    FheInt256,
    CompactCiphertextList,
    ProvenCompactCiphertextList,
} = require("../pkg/tfhe.js");
const {CompactPkeCrs, ZkComputeLoad} = require("../pkg");
const {
    randomBytes,
} = require('node:crypto');

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

    let builder = CompactCiphertextList.builder(publicKey);
    builder.push_i32(I32_MIN);
    let list = builder.build();
    let expander = list.expand();
    let encrypted = expander.get_int32(0);

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


function generateRandomBigInt(bitLength) {
    const bytesNeeded = Math.ceil(bitLength / 8);
    const randomBytesBuffer = randomBytes(bytesNeeded);

    // Convert random bytes to BigInt
    const randomBigInt = BigInt(`0x${randomBytesBuffer.toString('hex')}`);

    return randomBigInt;
}

test('hlapi_compact_ciphertext_list', (t) => {
    let config = TfheConfigBuilder.default()
        .build();

    let clientKey = TfheClientKey.generate(config);
    let publicKey = TfheCompactPublicKey.new(clientKey);

    let clear_u2 = 3;
    let clear_i32 = -3284;
    let clear_bool = true;
    let clear_u256 = generateRandomBigInt(256);

    let builder = CompactCiphertextList.builder(publicKey);
    builder.push_u2(clear_u2);
    builder.push_i32(clear_i32);
    builder.push_boolean(clear_bool);
    builder.push_u256(clear_u256);
    let list = builder.build();

    let serialized = list.safe_serialize(BigInt(10000000));
    let deserialized = CompactCiphertextList.safe_deserialize(serialized, BigInt(10000000));

    let expander = deserialized.expand();

    assert.deepStrictEqual(
        expander.get_uint2(0).decrypt(clientKey),
        clear_u2,
    );

    assert.deepStrictEqual(
        expander.get_int32(1).decrypt(clientKey),
        clear_i32,
    );

    assert.deepStrictEqual(
        expander.get_bool(2).decrypt(clientKey),
        clear_bool,
    );

    assert.deepStrictEqual(
        expander.get_uint256(3).decrypt(clientKey),
        clear_u256,
    );
});

test('hlapi_compact_ciphertext_list_with_proof', (t) => {
    const block_params = new ShortintParameters(ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
    let config = TfheConfigBuilder.default()
        .use_custom_parameters(block_params)
        .build();

    let clientKey = TfheClientKey.generate(config);
    let publicKey = TfheCompactPublicKey.new(clientKey);

    let crs = CompactPkeCrs.from_parameters(block_params, 2 + 32 + 1 + 256);
    let public_params = crs.public_params();

    let clear_u2 = 3;
    let clear_i32 = -3284;
    let clear_bool = true;
    let clear_u256 = generateRandomBigInt(256);

    let builder = CompactCiphertextList.builder(publicKey);
    builder.push_u2(clear_u2);
    builder.push_i32(clear_i32);
    builder.push_boolean(clear_bool);
    builder.push_u256(clear_u256);
    let list = builder.build_with_proof(public_params, ZkComputeLoad.Proof);

    let serialized = list.safe_serialize(BigInt(10000000));
    let deserialized = ProvenCompactCiphertextList.safe_deserialize(serialized, BigInt(10000000));

    let expander = deserialized.verify_and_expand(public_params, publicKey);

    assert.deepStrictEqual(
        expander.get_uint2(0).decrypt(clientKey),
        clear_u2,
    );

    assert.deepStrictEqual(
        expander.get_int32(1).decrypt(clientKey),
        clear_i32,
    );

    assert.deepStrictEqual(
        expander.get_bool(2).decrypt(clientKey),
        clear_bool,
    );

    assert.deepStrictEqual(
        expander.get_uint256(3).decrypt(clientKey),
        clear_u256,
    );
});


import * as Comlink from 'comlink';
import init, {
    initThreadPool,
    init_panic_hook,
    ShortintParametersName,
    ShortintParameters,
    TfheClientKey,
    TfhePublicKey,
    TfheCompressedPublicKey,
    TfheCompressedServerKey,
    TfheCompressedCompactPublicKey,
    TfheCompactPublicKey,
    TfheConfigBuilder,
    CompressedFheUint8,
    FheUint8,
    FheUint32,
    CompactFheUint32,
    CompactFheUint32List,
    CompressedFheUint128,
    FheUint128,
    CompressedFheUint256,
    FheUint256,
    CompactFheUint256,
    CompactFheUint256List,
} from "./pkg/tfhe.js";

function assert(cond, text){
    if( cond )	return;
	if( console.assert.useDebugger )	debugger;
	throw new Error(text || "Assertion failed!");
};

function assert_eq(a, b, text){
    if( a === b )	return;
	if( console.assert.useDebugger )	debugger;
	throw new Error(text || `Equality assertion failed!: ${a} != ${b}`);
};

async function compressedPublicKeyTest() {
    let config = TfheConfigBuilder.all_disabled()
        .enable_default_integers_small()
        .build();

    console.time('ClientKey Gen')
    let clientKey = TfheClientKey.generate(config);
    console.timeEnd('ClientKey Gen')
    
    console.time('CompressedPublicKey Gen')
    let compressedPublicKey = TfheCompressedPublicKey.new(clientKey);
    console.timeEnd('CompressedPublicKey Gen')

    let data = compressedPublicKey.serialize()
    console.log("CompressedPublicKey size:", data.length)

    console.time('CompressedPublicKey Decompression')
    let publicKey = compressedPublicKey.decompress();
    console.timeEnd('CompressedPublicKey Decompression')

    console.time('FheUint8 encrypt with CompressedPublicKey')
    let encrypted = FheUint8.encrypt_with_public_key(255, publicKey);
    console.timeEnd('FheUint8 encrypt with CompressedPublicKey')

    let ser = encrypted.serialize();
    console.log("Ciphertext Size", ser.length);

    let decrypted = encrypted.decrypt(clientKey);
    assert_eq(decrypted, 255)
}

async function publicKeyTest() {
    let config = TfheConfigBuilder.all_disabled()
        .enable_default_integers_small()
        .build();

    console.time('ClientKey Gen')
    let clientKey = TfheClientKey.generate(config);
    console.timeEnd('ClientKey Gen')

    console.time('PublicKey Gen')
    let publicKey = TfhePublicKey.new(clientKey);
    console.timeEnd('PublicKey Gen')

    console.time('FheUint8 encrypt with PublicKey')
    let encrypted = FheUint8.encrypt_with_public_key(255, publicKey);
    console.timeEnd('FheUint8 encrypt with PublicKey')

    let ser = encrypted.serialize();
    console.log("Ciphertext Size", ser.length);

    let decrypted = encrypted.decrypt(clientKey);
    assert_eq(decrypted, 255)
}

const U32_MAX = 4294967295;

async function compactPublicKeyTest32BitOnConfig(config) {
    console.time('ClientKey Gen')
    let clientKey = TfheClientKey.generate(config);
    console.timeEnd('ClientKey Gen')

    console.time('CompactPublicKey Gen')
    let publicKey = TfheCompactPublicKey.new(clientKey);
    console.timeEnd('CompactPublicKey Gen')

    let serialized_pk = publicKey.serialize();
    console.log("Serialized CompactPublicKey size: ", serialized_pk.length);

    let values = [0, 1, 2394, U32_MAX];

    console.time('CompactFheUint32List Encrypt')
    let compact_list = CompactFheUint32List.encrypt_with_compact_public_key(values, publicKey);
    console.timeEnd('CompactFheUint32List Encrypt')

    {
        console.time('CompactFheUint32List Expand')
        let encrypted_list = compact_list.expand();
        console.timeEnd('CompactFheUint32List Expand')

        assert_eq(encrypted_list.length, values.length);

        for (let i = 0; i < values.length; i++)
        {
            let decrypted = encrypted_list[i].decrypt(clientKey);
            assert_eq(decrypted, values[i]);
        }
    }

    let serialized_list = compact_list.serialize();
    console.log("Serialized CompactFheUint32List size: ", serialized_list.length);

    let deserialized_list = CompactFheUint32List.deserialize(serialized_list);
    let encrypted_list = deserialized_list.expand();
    assert_eq(encrypted_list.length, values.length);

    for (let i = 0; i < values.length; i++)
    {
        let decrypted = encrypted_list[i].decrypt(clientKey);
        assert_eq(decrypted, values[i]);
    }
}

async function compactPublicKeyTest32BitBig() {
    const block_params = new ShortintParameters(ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK);
    let config = TfheConfigBuilder.all_disabled()
        .enable_custom_integers(block_params)
        .build();
    await compactPublicKeyTest32BitOnConfig(config)
}

async function compactPublicKeyTest32BitSmall() {
    const block_params = new ShortintParameters(ShortintParametersName.PARAM_SMALL_MESSAGE_2_CARRY_2_COMPACT_PK);
    let config = TfheConfigBuilder.all_disabled()
        .enable_custom_integers(block_params)
        .build();
    await compactPublicKeyTest32BitOnConfig(config)
}

async function compactPublicKeyTest256BitOnConfig(config) {
    console.time('ClientKey Gen')
    let clientKey = TfheClientKey.generate(config);
    console.timeEnd('ClientKey Gen')

    console.time('CompactPublicKey Gen')
    let publicKey = TfheCompactPublicKey.new(clientKey);
    console.timeEnd('CompactPublicKey Gen')

    let serialized_pk = publicKey.serialize();
    console.log("Serialized CompactPublicKey size: ", serialized_pk.length);

    let values = [0, 1, 2394, U32_MAX].map((e) => BigInt(e));

    console.time('CompactFheUint256List Encrypt')
    let compact_list = CompactFheUint256List.encrypt_with_compact_public_key(values, publicKey);
    console.timeEnd('CompactFheUint256List Encrypt')

    {
        console.time('CompactFheUint256List Expand')
        let encrypted_list = compact_list.expand();
        console.timeEnd('CompactFheUint256List Expand')

        assert_eq(encrypted_list.length, values.length);

        for (let i = 0; i < values.length; i++)
        {
            let decrypted = encrypted_list[i].decrypt(clientKey);
            assert_eq(decrypted, values[i]);
        }
    }

    let serialized_list = compact_list.serialize();
    console.log("Serialized CompactFheUint256List size: ", serialized_list.length);

    let deserialized_list = CompactFheUint256List.deserialize(serialized_list);
    let encrypted_list = deserialized_list.expand();
    assert_eq(encrypted_list.length, values.length);

    for (let i = 0; i < values.length; i++)
    {
        let decrypted = encrypted_list[i].decrypt(clientKey);
        assert_eq(decrypted, values[i]);
    }
}

async function compactPublicKeyTest256BitBig() {
    const block_params = new ShortintParameters(ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK);
    let config = TfheConfigBuilder.all_disabled()
        .enable_custom_integers(block_params)
        .build();
    await compactPublicKeyTest256BitOnConfig(config)
}

async function compactPublicKeyTest256BitSmall() {
    const block_params = new ShortintParameters(ShortintParametersName.PARAM_SMALL_MESSAGE_2_CARRY_2_COMPACT_PK);
    let config = TfheConfigBuilder.all_disabled()
        .enable_custom_integers(block_params)
        .build();
    await compactPublicKeyTest256BitOnConfig(config)
}


async function compressedCompactPublicKeyTest256BitOnConfig(config) {
    console.time('ClientKey Gen')
    let clientKey = TfheClientKey.generate(config);
    console.timeEnd('ClientKey Gen')

    console.time('CompressedCompactPublicKey Gen')
    let publicKey = TfheCompressedCompactPublicKey.new(clientKey);
    console.timeEnd('CompressedCompactPublicKey Gen')

    let serialized_pk = publicKey.serialize();
    console.log("Serialized CompressedCompactPublicKey size: ", serialized_pk.length);

    console.time('CompressedCompactPublicKey Decompression')
    publicKey = publicKey.decompress()
    console.timeEnd('CompressedCompactPublicKey Decompression')

    let values = [0, 1, 2394, U32_MAX].map((e) => BigInt(e));

    console.time('CompactFheUint256List Encrypt')
    let compact_list = CompactFheUint256List.encrypt_with_compact_public_key(values, publicKey);
    console.timeEnd('CompactFheUint256List Encrypt')

    {
        console.time('CompactFheUint256List Expand')
        let encrypted_list = compact_list.expand();
        console.timeEnd('CompactFheUint256List Expand')

        assert_eq(encrypted_list.length, values.length);

        for (let i = 0; i < values.length; i++)
        {
            let decrypted = encrypted_list[i].decrypt(clientKey);
            assert_eq(decrypted, values[i]);
        }
    }

    let serialized_list = compact_list.serialize();
    console.log("Serialized CompactFheUint256List size: ", serialized_list.length);

    let deserialized_list = CompactFheUint256List.deserialize(serialized_list);
    let encrypted_list = deserialized_list.expand();
    assert_eq(encrypted_list.length, values.length);

    for (let i = 0; i < values.length; i++)
    {
        let decrypted = encrypted_list[i].decrypt(clientKey);
        assert_eq(decrypted, values[i]);
    }
}

async function compressedCompactPublicKeyTest256BitBig() {
    const block_params = new ShortintParameters(ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_COMPACT_PK);
    let config = TfheConfigBuilder.all_disabled()
        .enable_custom_integers(block_params)
        .build();
    await compressedCompactPublicKeyTest256BitOnConfig(config)
}

async function compressedCompactPublicKeyTest256BitSmall() {
    const block_params = new ShortintParameters(ShortintParametersName.PARAM_SMALL_MESSAGE_2_CARRY_2_COMPACT_PK);
    let config = TfheConfigBuilder.all_disabled()
        .enable_custom_integers(block_params)
        .build();
    await compressedCompactPublicKeyTest256BitOnConfig(config)
}



async function main() {
    await init()
    await initThreadPool(navigator.hardwareConcurrency);
    await init_panic_hook();

    return Comlink.proxy({
        publicKeyTest,
        compressedPublicKeyTest,
        compactPublicKeyTest32BitSmall,
        compactPublicKeyTest32BitBig,
        compactPublicKeyTest256BitSmall,
        compactPublicKeyTest256BitBig,
        compressedCompactPublicKeyTest256BitSmall,
        compressedCompactPublicKeyTest256BitBig,
    })
}

Comlink.expose({
    demos: main()
})

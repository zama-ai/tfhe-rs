
import * as Comlink from 'comlink';
import init, {
    initThreadPool,
    init_panic_hook,
    TfheClientKey,
    TfhePublicKey,
    TfheCompressedPublicKey,
    TfheCompressedServerKey,
    TfheConfigBuilder,
    CompressedFheUint8,
    FheUint8,
    FheUint32,
    CompressedFheUint128,
    FheUint128,
    CompressedFheUint256,
    FheUint256
} from "./pkg/tfhe.js";

function assert(cond, text){
    if( cond )	return;
	if( console.assert.useDebugger )	debugger;
	throw new Error(text || "Assertion failed!");
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
    assert(decrypted === 255)
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

    let data = publicKey.serialize()
    console.log("PublicKey size:", data.length)
    data = null;

    console.time('FheUint8 encrypt with PublicKey')
    let encrypted = FheUint8.encrypt_with_public_key(255, publicKey);
    console.timeEnd('FheUint8 encrypt with PublicKey')

    let ser = encrypted.serialize();
    console.log("Ciphertext Size", ser.length);

    let decrypted = encrypted.decrypt(clientKey);
    assert(decrypted === 255)
}

async function main() {
    await init()
    await initThreadPool(navigator.hardwareConcurrency);
    await init_panic_hook();

    return Comlink.proxy({
        publicKeyTest,
        compressedPublicKeyTest
    })
}

Comlink.expose({
    demos: main()
})

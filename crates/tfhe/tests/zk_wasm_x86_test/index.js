const {
    TfheCompactPublicKey,
    CompactCiphertextList,
    CompactPkeCrs,
    ZkComputeLoad,
} = require('node-tfhe');

const fs = require('fs');

const SIZE_LIMIT = BigInt(1024) * BigInt(1024) * BigInt(1024);
const METADATA = "wasm64";

const tfhe_proof = async () => {
    const publicKeyBuf = fs.readFileSync(`${__dirname}/public_key.bin`);
    const publicParamsBuf = fs.readFileSync(`${__dirname}/crs.bin`);
    const publicKey = TfheCompactPublicKey.safe_deserialize(publicKeyBuf, SIZE_LIMIT);
    const publicParams = CompactPkeCrs.safe_deserialize(publicParamsBuf, SIZE_LIMIT);

    const builder = CompactCiphertextList.builder(publicKey);
    builder.push_u4(1);
    builder.push_u8(0xff);

    const metadata = Uint8Array.from(METADATA.split('').map(letter => letter.charCodeAt(0)));

    const encrypted = builder.build_with_proof_packed(
        publicParams,
        metadata,
        ZkComputeLoad.Proof,
    );

    const ciphertext = encrypted.safe_serialize(SIZE_LIMIT);
    let ciphertext_hex = Buffer.from(ciphertext);


    fs.writeFile('proof.bin', ciphertext_hex, (err) => {

        if (err) throw err;
    });
}
tfhe_proof();

import { assertEq, SIZE_LIMIT } from "../../shared/helper.js";
import { makeConfig } from "../config.js";

export function makePublicKeyDemos(pkg) {
  const {
    FheUint8,
    ShortintParametersName,
    TfheClientKey,
    TfheCompressedPublicKey,
    TfhePublicKey,
  } = pkg;
  const { get_tfhe_config } = makeConfig(pkg);

  async function compressedPublicKeyTest() {
    const config = get_tfhe_config(
      ShortintParametersName.V1_6_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M128,
    );

    console.time("ClientKey Gen");
    const clientKey = TfheClientKey.generate(config);
    console.timeEnd("ClientKey Gen");

    console.time("CompressedPublicKey Gen");
    const compressedPublicKey = TfheCompressedPublicKey.new(clientKey);
    console.timeEnd("CompressedPublicKey Gen");

    const data = compressedPublicKey.safe_serialize(SIZE_LIMIT);
    console.log("CompressedPublicKey size:", data.length);

    console.time("CompressedPublicKey Decompression");
    const publicKey = compressedPublicKey.decompress();
    console.timeEnd("CompressedPublicKey Decompression");

    console.time("FheUint8 encrypt with CompressedPublicKey");
    const encrypted = FheUint8.encrypt_with_public_key(255, publicKey);
    console.timeEnd("FheUint8 encrypt with CompressedPublicKey");

    const ser = encrypted.safe_serialize(SIZE_LIMIT);
    console.log("Ciphertext Size", ser.length);

    const decrypted = encrypted.decrypt(clientKey);
    assertEq(decrypted, 255);
  }

  async function publicKeyTest() {
    const config = get_tfhe_config(
      ShortintParametersName.V1_6_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M128,
    );

    console.time("ClientKey Gen");
    const clientKey = TfheClientKey.generate(config);
    console.timeEnd("ClientKey Gen");

    console.time("PublicKey Gen");
    const publicKey = TfhePublicKey.new(clientKey);
    console.timeEnd("PublicKey Gen");

    console.time("FheUint8 encrypt with PublicKey");
    const encrypted = FheUint8.encrypt_with_public_key(255, publicKey);
    console.timeEnd("FheUint8 encrypt with PublicKey");

    const ser = encrypted.safe_serialize(SIZE_LIMIT);
    console.log("Ciphertext Size", ser.length);

    const decrypted = encrypted.decrypt(clientKey);
    assertEq(decrypted, 255);
  }

  return { compressedPublicKeyTest, publicKeyTest };
}

import {
  generateMetadata,
  generateRandomBigInt,
  SIZE_LIMIT_LARGE,
} from "../../shared/helper.js";
import { runZkProofRoundtrip } from "../../shared/zk-roundtrip.js";
import { makeConfig } from "../config.js";

export function makeZkDemos(pkg) {
  const {
    CompactPkeCrs,
    set_server_key,
    ShortintCompactPublicKeyEncryptionParametersName,
    ShortintParametersName,
    TfheClientKey,
    TfheCompactPublicKey,
    TfheServerKey,
  } = pkg;
  const { get_tfhe_config_with_casting } = makeConfig(pkg);

  async function compactPublicKeyZeroKnowledgeTest() {
    const config = get_tfhe_config_with_casting(
      ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
      ShortintCompactPublicKeyEncryptionParametersName.PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    );

    const clientKey = TfheClientKey.generate(config);
    const serverKey = TfheServerKey.new(clientKey);
    const publicKey = TfheCompactPublicKey.new(clientKey);
    set_server_key(serverKey);

    console.log("Start CRS generation");
    console.time("CRS generation");
    const crs = CompactPkeCrs.from_config(config, 4 * 64);
    console.timeEnd("CRS generation");

    // Round-trip the CRS itself to make sure serialization works.
    const crsSerialized = crs.safe_serialize(SIZE_LIMIT_LARGE);
    console.log("CompactPkeCrs size:", crsSerialized.length);
    CompactPkeCrs.safe_deserialize(crsSerialized, SIZE_LIMIT_LARGE);

    const metadata = generateMetadata();

    // Single u64 input
    {
      const r = await runZkProofRoundtrip({
        pkg,
        clientKey,
        publicKey,
        crs,
        metadata,
        inputs: [generateRandomBigInt(64)],
        alsoTestUnverifiedExpand: true,
      });
      console.log(
        `Time to encrypt + prove CompactFheUint64: ${r.timing_ms} ms`,
      );
      console.log(`CompactCiphertextList size: ${r.serialized_size}`);
    }

    // Batch of 4 u64 inputs
    {
      const r = await runZkProofRoundtrip({
        pkg,
        clientKey,
        publicKey,
        crs,
        metadata,
        inputs: Array.from({ length: 4 }, () => generateRandomBigInt(64)),
        alsoTestUnverifiedExpand: true,
      });
      console.log(
        `Time to encrypt + prove CompactFheUint64List of 4: ${r.timing_ms} ms`,
      );
    }
  }

  async function asyncMainThreadCompactPublicKeyZeroKnowledgeTest() {
    const config = get_tfhe_config_with_casting(
      ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
      ShortintCompactPublicKeyEncryptionParametersName.PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    );

    const clientKey = TfheClientKey.generate(config);
    const serverKey = TfheServerKey.new(clientKey);
    const publicKey = TfheCompactPublicKey.new(clientKey);
    set_server_key(serverKey);

    console.log("Start CRS generation");
    console.time("CRS generation");
    const crs = CompactPkeCrs.from_config(config, 4 * 64);
    console.timeEnd("CRS generation");

    const metadata = generateMetadata();

    // Single u64 input
    {
      const r = await runZkProofRoundtrip({
        pkg,
        clientKey,
        publicKey,
        crs,
        metadata,
        inputs: [generateRandomBigInt(64)],
        asyncProof: true,
      });
      console.log(
        `Time to encrypt + prove (async, main thread) CompactFheUint64: ${r.timing_ms} ms`,
      );
      console.log(`CompactCiphertextList size: ${r.serialized_size}`);
    }

    // Batch of 4 u64 inputs
    {
      const r = await runZkProofRoundtrip({
        pkg,
        clientKey,
        publicKey,
        crs,
        metadata,
        inputs: Array.from({ length: 4 }, () => generateRandomBigInt(64)),
        asyncProof: true,
      });
      console.log(
        `Time to encrypt + prove (async, main thread) CompactFheUint64List of 4: ${r.timing_ms} ms`,
      );
    }
  }

  return {
    compactPublicKeyZeroKnowledgeTest,
    asyncMainThreadCompactPublicKeyZeroKnowledgeTest,
  };
}

import { bench, SIZE_LIMIT, U32_MAX } from "../../shared/helper.js";
import { makeConfig } from "../config.js";

export function makeCompactKeyBenches(pkg) {
  const {
    CompactCiphertextList,
    shortint_params_name,
    ShortintParametersName,
    TfheClientKey,
    TfheCompactPublicKey,
  } = pkg;
  const { get_tfhe_config } = makeConfig(pkg);

  /**
   * Benchmark compact public key generation + compact list encrypt + serialization.
   * `sizeLabel` is only used to tag the bench result IDs (e.g. "32", "256");
   * the underlying crypto is the same — only the params_name differs at call sites.
   */
  async function compactPublicKeyBench(params_name, sizeLabel) {
    const bench_loops = 100;
    const bench_results = {};

    const params_name_str = shortint_params_name(params_name);
    const config = get_tfhe_config(params_name);

    const clientKey = TfheClientKey.generate(config);
    const publicKey = TfheCompactPublicKey.new(clientKey);

    const timing_1 = await bench(
      () => TfheCompactPublicKey.new(clientKey),
      bench_loops,
    );
    console.log(
      `CompactPublicKey Gen bench (${sizeLabel}bit): `,
      timing_1,
      " ms",
    );
    bench_results[
      `compact_public_key_gen::${params_name_str}::${sizeLabel}bit_mean`
    ] = timing_1;

    const values = [0, 1, 2, 2394, U32_MAX].map(BigInt);

    let compact_list;
    const timing_2 = await bench(() => {
      const builder = CompactCiphertextList.builder(publicKey);
      for (const value of values) {
        builder.push_u256(value);
      }
      compact_list = builder.build();
    }, bench_loops);
    console.log(
      `CompactFheUint${sizeLabel}List Encrypt bench: `,
      timing_2,
      " ms",
    );
    bench_results[
      `compact_list_encrypt::${params_name_str}::fheuint${sizeLabel}_mean`
    ] = timing_2;

    const serialized_list = compact_list.safe_serialize(SIZE_LIMIT);
    console.log(
      `Serialized CompactFheUint${sizeLabel}List size: `,
      serialized_list.length,
    );

    const timing_3 = await bench(
      () => compact_list.safe_serialize(SIZE_LIMIT),
      bench_loops,
    );
    console.log(
      `CompactFheUint${sizeLabel}List serialization bench: `,
      timing_3,
      " ms",
    );
    bench_results[
      `compact_list_serialization::${params_name_str}::fheuint${sizeLabel}_mean`
    ] = timing_3;

    return bench_results;
  }

  async function compactPublicKeyBench32BitBig() {
    return await compactPublicKeyBench(
      ShortintParametersName.V1_6_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
      "32",
    );
  }

  async function compactPublicKeyBench32BitSmall() {
    return await compactPublicKeyBench(
      ShortintParametersName.V1_6_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M128,
      "32",
    );
  }

  async function compactPublicKeyBench256BitBig() {
    return await compactPublicKeyBench(
      ShortintParametersName.V1_6_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_GAUSSIAN_2M128,
      "256",
    );
  }

  async function compactPublicKeyBench256BitSmall() {
    return await compactPublicKeyBench(
      ShortintParametersName.V1_6_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M128,
      "256",
    );
  }

  return {
    compactPublicKeyBench32BitBig,
    compactPublicKeyBench32BitSmall,
    compactPublicKeyBench256BitBig,
    compactPublicKeyBench256BitSmall,
  };
}

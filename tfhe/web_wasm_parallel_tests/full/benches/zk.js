import { threads } from "wasm-feature-detect";
import { generateMetadata, SIZE_LIMIT, U64_MAX } from "../../shared/helper.js";
import { makeConfig } from "../config.js";

export function makeZkBenches(pkg) {
  const {
    CompactPkeCrs,
    ProvenCompactCiphertextList,
    shortint_params_name,
    ShortintCompactPublicKeyEncryptionParametersName,
    ShortintParametersName,
    TfheClientKey,
    TfheCompactPublicKey,
    ZkComputeLoad,
  } = pkg;
  const { get_tfhe_config_with_casting } = makeConfig(pkg);

  const LOAD_CHOICES = [ZkComputeLoad.Proof, ZkComputeLoad.Verify];
  const LOAD_TO_STR = {
    [ZkComputeLoad.Proof]: "compute_load_proof",
    [ZkComputeLoad.Verify]: "compute_load_verify",
  };

  const PROOF_CONFIGS = [
    { crs_bit_size: 64, bits_to_encrypt: [64] },
    // 64 * 4 is a production use-case
    { crs_bit_size: 2048, bits_to_encrypt: [64, 4 * 64, 2048] },
    { crs_bit_size: 4096, bits_to_encrypt: [4096] },
  ];

  async function compactPublicKeyZeroKnowledgeBench() {
    // Computed inside the function because `shortint_params_name` is a wasm
    // call that requires the wasm runtime to be initialized first.
    const PARAMS_TO_BENCH = [
      {
        zk_scheme: "ZKV2",
        name_str: shortint_params_name(
          ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        ),
        block_params_name:
          ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        casting_params_name:
          ShortintCompactPublicKeyEncryptionParametersName.PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
      },
    ];

    const bench_results = {};

    for (const params of PARAMS_TO_BENCH) {
      const block_params_name_str = params.name_str;
      const config = get_tfhe_config_with_casting(
        params.block_params_name,
        params.casting_params_name,
      );

      const clientKey = TfheClientKey.generate(config);
      const publicKey = TfheCompactPublicKey.new(clientKey);

      const bench_loops = 5; // The computation is expensive

      for (const proof_config of PROOF_CONFIGS) {
        console.log("Start CRS generation");
        console.time("CRS generation");
        const crs = CompactPkeCrs.from_config(
          config,
          proof_config.crs_bit_size,
        );
        console.timeEnd("CRS generation");

        const metadata = generateMetadata();

        for (const bits_to_encrypt of proof_config.bits_to_encrypt) {
          const encrypt_count = bits_to_encrypt / 64;
          const inputs = Array.from(Array(encrypt_count).keys()).map(
            () => U64_MAX,
          );

          for (const loadChoice of LOAD_CHOICES) {
            let serialized_size = 0;
            // NOTE: kept manual (no bench() helper) because we measure only the
            // build_with_proof_packed call, excluding the builder setup that
            // varies in cost with encrypt_count.
            let timing = 0;
            for (let i = 0; i < bench_loops; i++) {
              console.time(`Loop ${i}`);
              const compact_list_builder =
                ProvenCompactCiphertextList.builder(publicKey);
              for (let j = 0; j < encrypt_count; j++) {
                compact_list_builder.push_u64(inputs[j]);
              }
              const start = performance.now();
              const list = compact_list_builder.build_with_proof_packed(
                crs,
                metadata,
                loadChoice,
              );
              const end = performance.now();
              console.timeEnd(`Loop ${i}`);
              timing += end - start;
              serialized_size = list.safe_serialize(SIZE_LIMIT).length;
            }
            const mean = timing / bench_loops;

            const supportsThreads = await threads();
            const crsBits = proof_config.crs_bit_size;
            const loadStr = LOAD_TO_STR[loadChoice];
            const suffix = supportsThreads ? "" : "_cross_origin";

            const common_bench_str =
              `zk::pke_zk_proof::${block_params_name_str}::` +
              `${bits_to_encrypt}_bits_packed_${crsBits}_bits_crs_` +
              `${loadStr}_${params.zk_scheme}${suffix}`;

            const bench_str_1 = `${common_bench_str}_mean`;
            console.log(bench_str_1, ": ", mean, " ms");
            const bench_str_2 = `${common_bench_str}_serialized_size_mean`;
            console.log(bench_str_2, ": ", serialized_size, " bytes");

            bench_results[bench_str_1] = mean;
            bench_results[bench_str_2] = serialized_size;
          }
        }
      }
    }

    return bench_results;
  }

  return { compactPublicKeyZeroKnowledgeBench };
}

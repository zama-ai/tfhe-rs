import * as Comlink from "comlink";
import init, {
  init_panic_hook,
  shortint_params_name,
  ShortintParametersName,
  ShortintParameters,
  TfheClientKey,
  TfheCompactPublicKey,
  TfheConfigBuilder,
  ZkComputeLoad,
  CompactPkeCrs,
  ProvenCompactCiphertextList,
  ShortintCompactPublicKeyEncryptionParameters,
  ShortintCompactPublicKeyEncryptionParametersName,
} from "./pkg/tfhe.js";

const U64_MAX = BigInt("0xffffffffffffffff");

async function compactPublicKeyZeroKnowledgeBench() {
  let params_to_bench = [
    {
      zk_scheme: "ZKV2",
      name: shortint_params_name(
        ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
      ),
      block_params: new ShortintParameters(
        ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
      ),
      casting_params: new ShortintCompactPublicKeyEncryptionParameters(
        ShortintCompactPublicKeyEncryptionParametersName.PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
      ),
    },
  ];

  let bench_results = {};

  for (const params of params_to_bench) {
    let block_params_name = params.name;
    let block_params = params.block_params;
    let casting_params = params.casting_params;

    let config = TfheConfigBuilder.default()
      .use_custom_parameters(block_params)
      .use_dedicated_compact_public_key_parameters(casting_params)
      .build();

    let clientKey = TfheClientKey.generate(config);
    let publicKey = TfheCompactPublicKey.new(clientKey);

    const bench_loops = 5; // The computation is expensive
    let load_choices = [ZkComputeLoad.Proof, ZkComputeLoad.Verify];
    const load_to_str = {
      [ZkComputeLoad.Proof]: "compute_load_proof",
      [ZkComputeLoad.Verify]: "compute_load_verify",
    };

    // Proof configuration:
    let proof_configs = [
      { crs_bit_size: 64, bits_to_encrypt: [64] },
      // 64 * 4 is a production use-case
      { crs_bit_size: 2048, bits_to_encrypt: [64, 4 * 64, 2048] },
      { crs_bit_size: 4096, bits_to_encrypt: [4096] },
    ];

    for (const proof_config of proof_configs) {
      console.log("Start CRS generation");
      console.time("CRS generation");
      let crs = CompactPkeCrs.from_config(config, proof_config["crs_bit_size"]);
      console.timeEnd("CRS generation");

      // 320 bits is a use case we have, 8 bits per byte
      const metadata = new Uint8Array(320 / 8);
      crypto.getRandomValues(metadata);

      for (const bits_to_encrypt of proof_config["bits_to_encrypt"]) {
        let encrypt_count = bits_to_encrypt / 64;

        let inputs = Array.from(Array(encrypt_count).keys()).map(
          (_) => U64_MAX,
        );
        for (const loadChoice of load_choices) {
          let timing = 0;
          for (let i = 0; i < bench_loops; i++) {
            console.time("Loop " + i);
            let compact_list_builder =
              ProvenCompactCiphertextList.builder(publicKey);
            for (let j = 0; j < encrypt_count; j++) {
              compact_list_builder.push_u64(inputs[j]);
            }
            const start = performance.now();
            let list = compact_list_builder.build_with_proof_packed(
              crs,
              metadata,
              loadChoice,
            );
            const end = performance.now();
            console.timeEnd("Loop " + i);
            timing += end - start;
          }
          const mean = timing / bench_loops;
          const common_bench_str =
            "compact_fhe_uint_proven_encryption_unsafe_coop_" +
            params.zk_scheme +
            "_" +
            bits_to_encrypt +
            "_bits_packed_" +
            proof_config["crs_bit_size"] +
            "_bits_crs_" +
            load_to_str[loadChoice];
          const bench_str_1 = common_bench_str + "_mean_" + block_params_name;
          console.log(bench_str_1, ": ", mean, " ms");

          bench_results[bench_str_1] = mean;
        }
      }
    }
  }

  return bench_results;
}

async function main() {
  await init();
  await init_panic_hook();

  return Comlink.proxy({
    compactPublicKeyZeroKnowledgeBench,
  });
}

Comlink.expose({
  demos: main(),
});

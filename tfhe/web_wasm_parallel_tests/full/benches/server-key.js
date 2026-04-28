import { bench, SIZE_LIMIT_LARGE } from "../../shared/helper.js";
import { makeConfig } from "../config.js";

export function makeServerKeyBenches(pkg) {
  const {
    shortint_params_name,
    ShortintParametersName,
    TfheClientKey,
    TfheCompressedServerKey,
  } = pkg;
  const { get_tfhe_config } = makeConfig(pkg);

  async function compressedServerKeyBench(params_name) {
    const bench_loops = 5;
    const bench_results = {};

    const params_name_str = shortint_params_name(params_name);
    const config = get_tfhe_config(params_name);

    const clientKey = TfheClientKey.generate(config);

    const timing_1 = await bench(
      () => TfheCompressedServerKey.new(clientKey),
      bench_loops,
    );
    console.log("CompressedServerKey Gen bench: ", timing_1, " ms");
    bench_results[`compressed_server_key_gen::${params_name_str}::mean`] =
      timing_1;

    const serverKey = TfheCompressedServerKey.new(clientKey);
    const serialized_key = serverKey.safe_serialize(SIZE_LIMIT_LARGE);
    console.log("Serialized ServerKey size: ", serialized_key.length);

    const timing_2 = await bench(
      () => serverKey.safe_serialize(SIZE_LIMIT_LARGE),
      bench_loops,
    );
    console.log("CompressedServerKey serialization bench: ", timing_2, " ms");
    bench_results[
      `compressed_server_key_serialization::${params_name_str}::mean`
    ] = timing_2;

    return bench_results;
  }

  async function compressedServerKeyBenchMessage1Carry1() {
    return await compressedServerKeyBench(
      ShortintParametersName.V1_6_PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M128,
    );
  }

  async function compressedServerKeyBenchMessage2Carry2() {
    return await compressedServerKeyBench(
      ShortintParametersName.V1_6_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    );
  }

  return {
    compressedServerKeyBenchMessage1Carry1,
    compressedServerKeyBenchMessage2Carry2,
  };
}

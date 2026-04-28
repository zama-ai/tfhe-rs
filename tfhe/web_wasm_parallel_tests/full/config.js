import {
  TfheConfigBuilder,
  ShortintParameters,
  ShortintCompactPublicKeyEncryptionParameters,
} from "../pkg/tfhe.js";

export function get_tfhe_config(params_name) {
  const block_params = new ShortintParameters(params_name);
  return TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .build();
}

export function get_tfhe_config_with_casting(
  block_params_name,
  casting_params_name,
) {
  const block_params = new ShortintParameters(block_params_name);
  const casting_params = new ShortintCompactPublicKeyEncryptionParameters(
    casting_params_name,
  );
  return TfheConfigBuilder.default()
    .use_custom_parameters(block_params)
    .use_dedicated_compact_public_key_parameters(casting_params)
    .build();
}

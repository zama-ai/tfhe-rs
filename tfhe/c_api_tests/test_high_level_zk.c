#include "tfhe.h"
#include <assert.h>
#include <stdlib.h>

int main(void) {
  // We want to use zk-proof, which requires bounded random distributions
  // tfhe-rs has the `TUniform` as an available bounded distribution.

  // Note that simply changing parameters like this does not yield secure parameters
  // Its only done for the example / tests
  ShortintPBSParameters params = SHORTINT_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
  assert(params.encryption_key_choice == ShortintEncryptionKeyChoiceBig);

  ShortintCompactPublicKeyEncryptionParameters pke_params = SHORTINT_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

  int status;

  ConfigBuilder *builder;
  status = config_builder_default(&builder);
  assert(status == 0);
  status = config_builder_use_custom_parameters(&builder, params);
  assert(status == 0);
  status = use_dedicated_compact_public_key_parameters(&builder, pke_params);
  assert(status == 0);

  Config *config;
  status = config_builder_build(builder, &config);
  assert(status == 0);

  // Compute the CRS
  // Note that we do that before generating the client key
  // as client_key_generate takes ownership of the config
  CompactPkeCrs *crs;
  size_t max_num_bits = 32;
  status = compact_pke_crs_from_config(config, max_num_bits, &crs);
  assert(status == 0);

#define METADATA_LEN 5
  uint8_t metadata[METADATA_LEN] = {'c', '-', 'a', 'p', 'i'};

  ClientKey *client_key;
  ServerKey *server_key;
  status = generate_keys(config, &client_key, &server_key);
  assert(status == 0);

  set_server_key(server_key);

  // zk proofs of encryption works only using the CompactPublicKey
  CompactPublicKey *pk;
  status = compact_public_key_new(client_key, &pk);
  assert(status == 0);

  // Then, we create the compact list
  ProvenCompactCiphertextList *compact_list = NULL;
  {
    CompactCiphertextListBuilder *builder;
    status = compact_ciphertext_list_builder_new(pk, &builder);
    assert(status == 0);

    // Push some values
    status = compact_ciphertext_list_builder_push_u32(builder, 38382);
    assert(status == 0);

    status = compact_ciphertext_list_builder_push_i64(builder, -1);
    assert(status == 0);

    status = compact_ciphertext_list_builder_push_bool(builder, true);
    assert(status == 0);

    status = compact_ciphertext_list_builder_push_u2(builder, 3);
    assert(status == 0);

    status = compact_ciphertext_list_builder_build_with_proof_packed(
        builder, crs, metadata, METADATA_LEN, ZkComputeLoadProof, &compact_list);
    assert(status == 0);

    // Don't forget to destroy the builder
    compact_ciphertext_list_builder_destroy(builder);
  }

  // Now we can expand values
  FheUint32 *a = NULL;
  FheInt64 *b = NULL;
  FheBool *c = NULL;
  FheUint2 *d = NULL;
  {
    CompactCiphertextListExpander *expander = NULL;
    status = proven_compact_ciphertext_list_verify_and_expand(compact_list, crs, pk,
                                                              metadata, METADATA_LEN, &expander);
    assert(status == 0);

    status = compact_ciphertext_list_expander_get_fhe_uint32(expander, 0, &a);
    assert(status == 0);

    status = compact_ciphertext_list_expander_get_fhe_int64(expander, 1, &b);
    assert(status == 0);

    status = compact_ciphertext_list_expander_get_fhe_bool(expander, 2, &c);
    assert(status == 0);

    status = compact_ciphertext_list_expander_get_fhe_uint2(expander, 3, &d);
    assert(status == 0);

    // Don't forget to destroy the expander
    compact_ciphertext_list_expander_destroy(expander);
  }

  uint32_t clear_a = 0;
  status = fhe_uint32_decrypt(a, client_key, &clear_a);
  assert(status == 0);
  assert(clear_a == 38382);

  int64_t clear_b = 0;
  status = fhe_int64_decrypt(b, client_key, &clear_b);
  assert(status == 0);
  assert(clear_b == -1);

  bool clear_c = false;
  status = fhe_bool_decrypt(c, client_key, &clear_c);
  assert(status == 0);
  assert(clear_c == true);

  uint8_t clear_d = 0;
  status = fhe_uint2_decrypt(d, client_key, &clear_d);
  assert(status == 0);
  assert(clear_d == 3);

  fhe_uint32_destroy(a);
  fhe_int64_destroy(b);
  fhe_bool_destroy(c);
  fhe_uint2_destroy(d);
  client_key_destroy(client_key);
  server_key_destroy(server_key);
  compact_public_key_destroy(pk);
  compact_pke_crs_destroy(crs);

  return EXIT_SUCCESS;
}

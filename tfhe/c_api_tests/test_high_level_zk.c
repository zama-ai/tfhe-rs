#include <tfhe.h>
#include <assert.h>
#include <stdlib.h>

int main(void) {
  // We want to use zk-proof, which requires bounded random distributions
  // tfhe-rs has the `TUniform` as an available bounded distribution.

  // Note that simply changing parameters like this does not yield secure parameters
  // Its only done for the example / tests
  ShortintPBSParameters params = SHORTINT_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS_TUNIFORM_2M40;
  assert(params.encryption_key_choice == ShortintEncryptionKeyChoiceBig);

  int status;

  ConfigBuilder *builder;
  status = config_builder_default(&builder);
  assert(status == 0);
  status = config_builder_use_custom_parameters(&builder, params);
  assert(status == 0);

  Config *config;
  status = config_builder_build(builder, &config);
  assert(status == 0);

  // Compute the CRS
  // Note that we do that before generating the client key
  // as client_key_generate thakes ownership of the config
  CompactPkeCrs *crs;
  size_t max_num_bits = 32;
  status = compact_pke_crs_from_config(config, max_num_bits, &crs);
  assert(status == 0);

  CompactPkePublicParams *public_params;
  status = compact_pke_crs_public_params(crs, &public_params);
  assert(status == 0);

  ClientKey *client_key;
  status = client_key_generate(config, &client_key);
  assert(status == 0);

  // zk proofs of encryption works only using the CompactPublicKey
  CompactPublicKey *pk;
  status = compact_public_key_new(client_key, &pk);
  assert(status == 0);

  // Demo of ProvenCompactFheUint32
  {
    uint32_t msg = 8328937;
    ProvenCompactFheUint32 *proven_fhe_uint;
    status = proven_compact_fhe_uint32_try_encrypt(msg, public_params, pk, ZkComputeLoadProof,
                                                   &proven_fhe_uint);
    assert(status == 0);

    FheUint32 *fhe_uint;
    // This function does not take ownership of the proven fhe uint, so we have to cleanup later
    status =
        proven_compact_fhe_uint32_verify_and_expand(proven_fhe_uint, public_params, pk, &fhe_uint);
    assert(status == 0);

    uint32_t decrypted;
    status = fhe_uint32_decrypt(fhe_uint, client_key, &decrypted);
    assert(status == 0);

    assert(decrypted == msg);
    fhe_uint32_destroy(fhe_uint);
    proven_compact_fhe_uint32_destroy(proven_fhe_uint);
  }

  // Demo of ProvenCompactFheUint32List
  {
    uint32_t msgs[4] = {8328937, 217521191, 2753219039, 91099540};
    ProvenCompactFheUint32List *proven_fhe_list;
    status = proven_compact_fhe_uint32_list_try_encrypt(msgs, 4, public_params, pk,
                                                        ZkComputeLoadProof, &proven_fhe_list);
    assert(status == 0);

    size_t list_len;
    status = proven_compact_fhe_uint32_list_len(proven_fhe_list, &list_len);
    assert(status == 0);
    assert(list_len == 4);

    FheUint32 *fhe_uints[4];
    // This function does not take ownership of the proven fhe uint, so we have to cleanup later
    status = proven_compact_fhe_uint32_list_verify_and_expand(proven_fhe_list, public_params, pk,
                                                              &fhe_uints[0], 4);
    assert(status == 0);

    for (size_t i = 0; i < 4; ++i) {
      uint32_t decrypted;
      status = fhe_uint32_decrypt(fhe_uints[i], client_key, &decrypted);
      assert(status == 0);

      assert(decrypted == msgs[i]);
      fhe_uint32_destroy(fhe_uints[i]);
    }

    proven_compact_fhe_uint32_list_destroy(proven_fhe_list);
  }

  compact_pke_public_params_destroy(public_params);
  compact_pke_crs_destroy(crs);
  compact_public_key_destroy(pk);
  client_key_destroy(client_key);

  return EXIT_SUCCESS;
}

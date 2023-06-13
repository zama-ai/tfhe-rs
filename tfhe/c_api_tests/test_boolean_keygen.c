#include "tfhe.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

void test_default_keygen_w_serde(void) {
  BooleanClientKey *cks = NULL;
  BooleanServerKey *sks = NULL;
  BooleanCiphertext *ct = NULL;
  Buffer ct_ser_buffer = {.pointer = NULL, .length = 0};
  BooleanCiphertext *deser_ct = NULL;
  BooleanCompressedCiphertext *cct = NULL;
  BooleanCompressedCiphertext *deser_cct = NULL;
  BooleanCiphertext *decompressed_ct = NULL;

  int gen_keys_ok = boolean_gen_keys_with_default_parameters(&cks, &sks);
  assert(gen_keys_ok == 0);

  int encrypt_ok = boolean_client_key_encrypt(cks, true, &ct);
  assert(encrypt_ok == 0);

  int ser_ok = boolean_serialize_ciphertext(ct, &ct_ser_buffer);
  assert(ser_ok == 0);

  BufferView deser_view = {.pointer = ct_ser_buffer.pointer, .length = ct_ser_buffer.length};

  int deser_ok = boolean_deserialize_ciphertext(deser_view, &deser_ct);
  assert(deser_ok == 0);

  assert(deser_view.length == ct_ser_buffer.length);
  for (size_t idx = 0; idx < deser_view.length; ++idx) {
    assert(deser_view.pointer[idx] == ct_ser_buffer.pointer[idx]);
  }

  bool result = false;
  int decrypt_ok = boolean_client_key_decrypt(cks, deser_ct, &result);
  assert(decrypt_ok == 0);

  assert(result == true);

  int c_encrypt_ok = boolean_client_key_encrypt_compressed(cks, true, &cct);
  assert(c_encrypt_ok == 0);

  int c_ser_ok = boolean_serialize_compressed_ciphertext(cct, &ct_ser_buffer);
  assert(c_ser_ok == 0);

  deser_view.pointer = ct_ser_buffer.pointer;
  deser_view.length = ct_ser_buffer.length;

  int c_deser_ok = boolean_deserialize_compressed_ciphertext(deser_view, &deser_cct);
  assert(c_deser_ok == 0);

  int decomp_ok = boolean_decompress_ciphertext(cct, &decompressed_ct);
  assert(decomp_ok == 0);

  bool c_result = false;
  int c_decrypt_ok = boolean_client_key_decrypt(cks, decompressed_ct, &c_result);
  assert(c_decrypt_ok == 0);

  assert(c_result == true);

  boolean_destroy_client_key(cks);
  boolean_destroy_server_key(sks);
  boolean_destroy_ciphertext(ct);
  boolean_destroy_ciphertext(deser_ct);
  boolean_destroy_compressed_ciphertext(cct);
  boolean_destroy_compressed_ciphertext(deser_cct);
  boolean_destroy_ciphertext(decompressed_ct);
  destroy_buffer(&ct_ser_buffer);
}

void test_predefined_keygen_w_serde(void) {
  BooleanClientKey *cks = NULL;
  BooleanServerKey *sks = NULL;

  int gen_keys_ok =
      boolean_gen_keys_with_parameters(BOOLEAN_PARAMETERS_SET_DEFAULT_PARAMETERS, &cks, &sks);

  assert(gen_keys_ok == 0);

  boolean_destroy_client_key(cks);
  boolean_destroy_server_key(sks);

  gen_keys_ok =
      boolean_gen_keys_with_parameters(BOOLEAN_PARAMETERS_SET_TFHE_LIB_PARAMETERS, &cks, &sks);

  assert(gen_keys_ok == 0);

  boolean_destroy_client_key(cks);
  boolean_destroy_server_key(sks);
}

void test_custom_keygen(void) {
  BooleanClientKey *cks = NULL;
  BooleanServerKey *sks = NULL;
  BooleanParameters params = {
      .lwe_dimension = 10,
      .glwe_dimension = 1,
      .polynomial_size = 1024,
      .lwe_modular_std_dev = 10e-100,
      .glwe_modular_std_dev = 10e-100,
      .pbs_base_log = 3,
      .pbs_level = 1,
      .ks_base_log = 4,
      .ks_level = 2,
  };

  int gen_keys_ok = boolean_gen_keys_with_parameters(params, &cks, &sks);

  assert(gen_keys_ok == 0);

  boolean_destroy_client_key(cks);
  boolean_destroy_server_key(sks);
}

void test_public_keygen(void) {
  BooleanClientKey *cks = NULL;
  BooleanPublicKey *pks = NULL;
  BooleanCiphertext *ct = NULL;

  int gen_keys_ok = boolean_gen_client_key(BOOLEAN_PARAMETERS_SET_DEFAULT_PARAMETERS, &cks);
  assert(gen_keys_ok == 0);

  int gen_pks = boolean_gen_public_key(cks, &pks);
  assert(gen_pks == 0);

  bool msg = true;

  int encrypt_ok = boolean_public_key_encrypt(pks, msg, &ct);
  assert(encrypt_ok == 0);

  bool result = false;
  int decrypt_ok = boolean_client_key_decrypt(cks, ct, &result);
  assert(decrypt_ok == 0);

  assert(result == true);

  boolean_destroy_client_key(cks);
  boolean_destroy_public_key(pks);
  boolean_destroy_ciphertext(ct);
}

int main(void) {
  test_default_keygen_w_serde();
  test_predefined_keygen_w_serde();
  test_custom_keygen();
  test_public_keygen();
  return EXIT_SUCCESS;
}

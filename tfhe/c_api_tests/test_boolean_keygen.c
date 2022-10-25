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

  int gen_keys_ok = booleans_gen_keys_with_default_parameters(&cks, &sks);
  assert(gen_keys_ok == 0);

  int encrypt_ok = booleans_client_key_encrypt(cks, true, &ct);
  assert(encrypt_ok == 0);

  int ser_ok = booleans_serialize_ciphertext(ct, &ct_ser_buffer);
  assert(ser_ok == 0);

  BufferView deser_view = {.pointer = ct_ser_buffer.pointer, .length = ct_ser_buffer.length};

  int deser_ok = booleans_deserialize_ciphertext(deser_view, &deser_ct);
  assert(deser_ok == 0);

  bool result = false;
  int decrypt_ok = booleans_client_key_decrypt(cks, deser_ct, &result);
  assert(decrypt_ok);

  assert(result == true);

  destroy_boolean_client_key(cks);
  destroy_boolean_server_key(sks);
  destroy_boolean_ciphertext(ct);
  destroy_boolean_ciphertext(deser_ct);
  destroy_buffer(&ct_ser_buffer);
}

void test_predefiend_keygen(void) {
  BooleanClientKey *cks = NULL;
  BooleanServerKey *sks = NULL;

  int gen_keys_ok = booleans_gen_keys_with_predefined_parameters_set(
      BOOLEAN_PARAMETERS_SET_DEFAULT_PARAMETERS, &cks, &sks);

  assert(gen_keys_ok == 0);

  destroy_boolean_client_key(cks);
  destroy_boolean_server_key(sks);

  gen_keys_ok = booleans_gen_keys_with_predefined_parameters_set(
      BOOLEAN_PARAMETERS_SET_THFE_LIB_PARAMETERS, &cks, &sks);

  assert(gen_keys_ok == 0);

  destroy_boolean_client_key(cks);
  destroy_boolean_server_key(sks);
}

void test_custom_keygen(void) {
  BooleanClientKey *cks = NULL;
  BooleanServerKey *sks = NULL;
  BooleanParameters *params = NULL;

  int params_ok = create_boolean_parameters(10, 1, 1024, 10e-100, 10e-100, 3, 1, 4, 2, &params);
  assert(params_ok == 0);

  int gen_keys_ok = booleans_gen_keys_with_parameters(params, &cks, &sks);

  assert(gen_keys_ok == 0);

  destroy_boolean_parameters(params);
  destroy_boolean_client_key(cks);
  destroy_boolean_server_key(sks);
}

int main(void) {
  test_default_keygen_w_serde();
  test_predefiend_keygen();
  test_custom_keygen();
  return EXIT_SUCCESS;
}

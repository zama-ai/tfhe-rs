#include "tfhe.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

void test_predefined_keygen_w_serde(void) {
  ShortintClientKey *cks = NULL;
  ShortintServerKey *sks = NULL;
  ShortintParameters *params = NULL;
  ShortintCiphertext *ct = NULL;
  Buffer ct_ser_buffer = {.pointer = NULL, .length = 0};
  ShortintCiphertext *deser_ct = NULL;

  int get_params_ok = shortints_get_parameters(2, 2, &params);
  assert(get_params_ok == 0);

  int gen_keys_ok = shortints_gen_keys_with_parameters(params, &cks, &sks);
  assert(gen_keys_ok == 0);

  int encrypt_ok = shortints_client_key_encrypt(cks, 3, &ct);
  assert(encrypt_ok == 0);

  int ser_ok = shortints_serialize_ciphertext(ct, &ct_ser_buffer);
  assert(ser_ok == 0);

  BufferView deser_view = {.pointer = ct_ser_buffer.pointer, .length = ct_ser_buffer.length};

  int deser_ok = shortints_deserialize_ciphertext(deser_view, &deser_ct);
  assert(deser_ok == 0);

  assert(deser_view.length == ct_ser_buffer.length);
  for (size_t idx = 0; idx < deser_view.length; ++idx) {
    assert(deser_view.pointer[idx] == ct_ser_buffer.pointer[idx]);
  }

  uint64_t result = -1;
  int decrypt_ok = shortints_client_key_decrypt(cks, deser_ct, &result);
  assert(decrypt_ok == 0);

  assert(result == 3);

  destroy_shortint_client_key(cks);
  destroy_shortint_server_key(sks);
  destroy_shortint_parameters(params);
  destroy_shortint_ciphertext(ct);
  destroy_shortint_ciphertext(deser_ct);
  destroy_buffer(&ct_ser_buffer);
}

void test_custom_keygen(void) {
  ShortintClientKey *cks = NULL;
  ShortintServerKey *sks = NULL;
  ShortintParameters *params = NULL;

  int params_ok = shortints_create_parameters(10, 1, 1024, 10e-100, 10e-100, 2, 3, 2, 3, 2, 3,
                                              10e-100, 2, 3, 2, 2, &params);
  assert(params_ok == 0);

  int gen_keys_ok = shortints_gen_keys_with_parameters(params, &cks, &sks);

  assert(gen_keys_ok == 0);

  destroy_shortint_parameters(params);
  destroy_shortint_client_key(cks);
  destroy_shortint_server_key(sks);
}

int main(void) {
  test_predefined_keygen_w_serde();
  test_custom_keygen();
  return EXIT_SUCCESS;
}

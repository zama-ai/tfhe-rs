#include "tfhe.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

void test_and(BooleanClientKey *cks, BooleanServerKey *sks) {
  for (int idx_left = 0; idx_left < 2; ++idx_left) {
    for (int idx_right = 0; idx_right < 2; ++idx_right) {
      BooleanCiphertext *ct_left = NULL;
      BooleanCiphertext *ct_right = NULL;
      BooleanCiphertext *ct_result = NULL;

      bool left = (bool)idx_left;
      bool right = (bool)idx_right;

      bool expected = left && right;

      int encrypt_left_ok = booleans_client_key_encrypt(cks, left, &ct_left);
      assert(encrypt_left_ok == 0);

      int encrypt_right_ok = booleans_client_key_encrypt(cks, right, &ct_right);
      assert(encrypt_right_ok == 0);

      int and_ok = booleans_server_key_and(sks, ct_left, ct_right, &ct_result);
      assert(and_ok == 0);

      bool decrypted_result = false;

      int decrypt_ok = booleans_client_key_decrypt(cks, ct_result, &decrypted_result);
      assert(decrypt_ok == 0);

      assert(decrypted_result == expected);

      destroy_boolean_ciphertext(ct_left);
      destroy_boolean_ciphertext(ct_right);
      destroy_boolean_ciphertext(ct_result);
    }
  }
}

void test_server_key(void) {
  BooleanClientKey *cks = NULL;
  BooleanServerKey *sks = NULL;

  int gen_keys_ok = booleans_gen_keys_with_default_parameters(&cks, &sks);
  assert(gen_keys_ok == 0);

  test_and(cks, sks);

  destroy_boolean_client_key(cks);
  destroy_boolean_server_key(sks);
}

int main(void) {
  test_server_key();
  return EXIT_SUCCESS;
}

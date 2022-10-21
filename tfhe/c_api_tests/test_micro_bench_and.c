#include "tfhe.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>
#include <time.h>

void micro_bench_and() {
  BooleanClientKey *cks = NULL;
  BooleanServerKey *sks = NULL;

  // int gen_keys_ok = boolean_gen_keys_with_default_parameters(&cks, &sks);
  // assert(gen_keys_ok == 0);

  int gen_keys_ok = boolean_gen_keys_with_predefined_parameters_set(
      BOOLEAN_PARAMETERS_SET_THFE_LIB_PARAMETERS, &cks, &sks);
  assert(gen_keys_ok == 0);

  int num_loops = 10000;

  BooleanCiphertext *ct_left = NULL;
  BooleanCiphertext *ct_right = NULL;

  int encrypt_left_ok = boolean_client_key_encrypt(cks, false, &ct_left);
  assert(encrypt_left_ok == 0);
  int encrypt_right_ok = boolean_client_key_encrypt(cks, true, &ct_right);
  assert(encrypt_right_ok == 0);

  clock_t start = clock();

  for (int idx_loops = 0; idx_loops < num_loops; ++idx_loops) {
    BooleanCiphertext *ct_result = NULL;
    boolean_server_key_and(sks, ct_left, ct_right, &ct_result);
    destroy_boolean_ciphertext(ct_result);
  }

  clock_t stop = clock();
  double elapsed_ms = (double)((stop - start) * 1000) / CLOCKS_PER_SEC;
  double mean_ms = elapsed_ms / num_loops;

  printf("%g ms, mean %g ms\n", elapsed_ms, mean_ms);

  destroy_boolean_client_key(cks);
  destroy_boolean_server_key(sks);
}

int main(void) {
  micro_bench_and();
  return EXIT_SUCCESS;
}

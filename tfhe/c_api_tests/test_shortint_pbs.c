#include "tfhe.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

uint64_t double_accumulator_2_bits_message(uint64_t in) { return (in * 2) % 4; }

void test_shortints_pbs_2_bits_message(void) {
  ShortintPBSAccumulator *accumulator = NULL;
  ShortintClientKey *cks = NULL;
  ShortintServerKey *sks = NULL;
  ShortintParameters *params = NULL;

  int get_params_ok = shortints_get_parameters(2, 2, &params);
  assert(get_params_ok == 0);

  int gen_keys_ok = shortints_gen_keys_with_parameters(params, &cks, &sks);
  assert(gen_keys_ok == 0);

  int gen_acc_ok = shortints_shortints_server_key_generate_pbs_accumulator(
      sks, double_accumulator_2_bits_message, &accumulator);
  assert(gen_acc_ok == 0);

  for (int in_idx = 0; in_idx < 4; ++in_idx) {
    ShortintCiphertext *ct = NULL;
    ShortintCiphertext *ct_out = NULL;

    uint64_t in_val = (uint64_t)in_idx;

    int encrypt_ok = shortints_client_key_encrypt(cks, in_val, &ct);
    assert(encrypt_ok == 0);

    int pbs_ok = shortints_server_key_programmable_bootstrap(sks, accumulator, ct, &ct_out);
    assert(pbs_ok == 0);

    uint64_t result_non_assign = -1;
    int decrypt_non_assign_ok = shortints_client_key_decrypt(cks, ct_out, &result_non_assign);
    assert(decrypt_non_assign_ok == 0);

    assert(result_non_assign == double_accumulator_2_bits_message(in_val));

    int pbs_assign_ok =
        shortints_server_key_programmable_bootstrap_assign(sks, accumulator, ct_out);
    assert(pbs_assign_ok == 0);

    uint64_t result_assign = -1;
    int decrypt_assign_ok = shortints_client_key_decrypt(cks, ct_out, &result_assign);
    assert(decrypt_assign_ok == 0);

    assert(result_assign == double_accumulator_2_bits_message(result_non_assign));

    destroy_shortint_ciphertext(ct);
    destroy_shortint_ciphertext(ct_out);
  }

  destroy_shortint_pbs_accumulator(accumulator);
  destroy_shortint_client_key(cks);
  destroy_shortint_server_key(sks);
  destroy_shortint_parameters(params);
}

int main(void) {
  test_shortints_pbs_2_bits_message();
  return EXIT_SUCCESS;
}

#include "tfhe.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

uint64_t double_lookup_table_2_bits_message(uint64_t in) { return (in * 2) % 4; }

uint64_t get_max_value_of_lookup_table_generator(uint64_t (*lookup_table_func)(uint64_t),
                                                 size_t message_bits) {
  uint64_t max_value = 0;
  for (size_t idx = 0; idx < (1 << message_bits); ++idx) {
    uint64_t acc_value = lookup_table_func((uint64_t)idx);
    max_value = acc_value > max_value ? acc_value : max_value;
  }

  return max_value;
}

uint64_t product_lookup_table_2_bits_encrypted_mul(uint64_t left, uint64_t right) {
  return (left * right) % 4;
}

uint64_t get_max_value_of_bivariate_lookup_table_generator(uint64_t (*lookup_table_func)(uint64_t,
                                                                                         uint64_t),
                                                           size_t message_bits_left,
                                                           size_t message_bits_right) {
  uint64_t max_value = 0;
  for (size_t idx_left = 0; idx_left < (1 << message_bits_left); ++idx_left) {
    for (size_t idx_right = 0; idx_right < (1 << message_bits_right); ++idx_right) {
      uint64_t acc_value = lookup_table_func((uint64_t)idx_left, (uint64_t)idx_right);
      max_value = acc_value > max_value ? acc_value : max_value;
    }
  }

  return max_value;
}

void test_shortint_pbs_2_bits_message(void) {
  ShortintPBSLookupTable *lookup_table = NULL;
  ShortintClientKey *cks = NULL;
  ShortintServerKey *sks = NULL;
  ShortintPBSParameters params = SHORTINT_PARAM_MESSAGE_2_CARRY_2_KS_PBS;

  int gen_keys_ok = shortint_gen_keys_with_parameters(params, &cks, &sks);
  assert(gen_keys_ok == 0);

  int gen_acc_ok = shortint_server_key_generate_pbs_lookup_table(
      sks, double_lookup_table_2_bits_message, &lookup_table);
  assert(gen_acc_ok == 0);

  for (int in_idx = 0; in_idx < 4; ++in_idx) {
    ShortintCiphertext *ct = NULL;
    ShortintCiphertext *ct_out = NULL;

    uint64_t in_val = (uint64_t)in_idx;

    int encrypt_ok = shortint_client_key_encrypt(cks, in_val, &ct);
    assert(encrypt_ok == 0);

    size_t degree = -1;
    int get_degree_ok = shortint_ciphertext_get_degree(ct, &degree);
    assert(get_degree_ok == 0);

    assert(degree == 3);

    int pbs_ok = shortint_server_key_programmable_bootstrap(sks, lookup_table, ct, &ct_out);
    assert(pbs_ok == 0);

    size_t degree_to_set =
        (size_t)get_max_value_of_lookup_table_generator(double_lookup_table_2_bits_message, 2);

    int set_degree_ok = shortint_ciphertext_set_degree(ct_out, degree_to_set);
    assert(set_degree_ok == 0);

    degree = -1;
    get_degree_ok = shortint_ciphertext_get_degree(ct_out, &degree);
    assert(get_degree_ok == 0);

    assert(degree == degree_to_set);

    uint64_t result_non_assign = -1;
    int decrypt_non_assign_ok = shortint_client_key_decrypt(cks, ct_out, &result_non_assign);
    assert(decrypt_non_assign_ok == 0);

    assert(result_non_assign == double_lookup_table_2_bits_message(in_val));

    int pbs_assign_ok =
        shortint_server_key_programmable_bootstrap_assign(sks, lookup_table, ct_out);
    assert(pbs_assign_ok == 0);

    degree_to_set =
        (size_t)get_max_value_of_lookup_table_generator(double_lookup_table_2_bits_message, 2);

    set_degree_ok = shortint_ciphertext_set_degree(ct_out, degree_to_set);
    assert(set_degree_ok == 0);

    uint64_t result_assign = -1;
    int decrypt_assign_ok = shortint_client_key_decrypt(cks, ct_out, &result_assign);
    assert(decrypt_assign_ok == 0);

    assert(result_assign == double_lookup_table_2_bits_message(result_non_assign));

    shortint_destroy_ciphertext(ct);
    shortint_destroy_ciphertext(ct_out);
  }

  shortint_destroy_pbs_lookup_table(lookup_table);
  shortint_destroy_client_key(cks);
  shortint_destroy_server_key(sks);
}

void test_shortint_bivariate_pbs_2_bits_message(void) {
  ShortintBivariatePBSLookupTable *lookup_table = NULL;
  ShortintClientKey *cks = NULL;
  ShortintServerKey *sks = NULL;
  ShortintPBSParameters params = SHORTINT_PARAM_MESSAGE_2_CARRY_2_KS_PBS;

  int gen_keys_ok = shortint_gen_keys_with_parameters(params, &cks, &sks);
  assert(gen_keys_ok == 0);

  int gen_acc_ok = shortint_server_key_generate_bivariate_pbs_lookup_table(
      sks, product_lookup_table_2_bits_encrypted_mul, &lookup_table);
  assert(gen_acc_ok == 0);

  for (int left_idx = 0; left_idx < 4; ++left_idx) {
    for (int right_idx = 0; right_idx < 4; ++right_idx) {
      ShortintCiphertext *ct_left = NULL;
      ShortintCiphertext *ct_right = NULL;
      ShortintCiphertext *ct_out = NULL;

      uint64_t left_val = (uint64_t)left_idx;
      uint64_t right_val = (uint64_t)right_idx;

      int encrypt_left_ok = shortint_client_key_encrypt(cks, left_val, &ct_left);
      assert(encrypt_left_ok == 0);

      int encrypt_right_ok = shortint_client_key_encrypt(cks, right_val, &ct_right);
      assert(encrypt_right_ok == 0);

      int pbs_ok = shortint_server_key_bivariate_programmable_bootstrap(sks, lookup_table, ct_left,
                                                                        ct_right, &ct_out);
      assert(pbs_ok == 0);

      size_t degree_to_set = (size_t)get_max_value_of_bivariate_lookup_table_generator(
          product_lookup_table_2_bits_encrypted_mul, 2, 2);

      int set_degree_ok = shortint_ciphertext_set_degree(ct_right, degree_to_set);
      assert(set_degree_ok == 0);

      uint64_t result_non_assign = -1;
      int decrypt_non_assign_ok = shortint_client_key_decrypt(cks, ct_out, &result_non_assign);
      assert(decrypt_non_assign_ok == 0);

      assert(result_non_assign == product_lookup_table_2_bits_encrypted_mul(left_val, right_val));

      int pbs_assign_ok = shortint_server_key_bivariate_programmable_bootstrap_assign(
          sks, lookup_table, ct_out, ct_right);
      assert(pbs_assign_ok == 0);

      degree_to_set =
          (size_t)get_max_value_of_lookup_table_generator(double_lookup_table_2_bits_message, 2);

      set_degree_ok = shortint_ciphertext_set_degree(ct_out, degree_to_set);
      assert(set_degree_ok == 0);

      uint64_t result_assign = -1;
      int decrypt_assign_ok = shortint_client_key_decrypt(cks, ct_out, &result_assign);
      assert(decrypt_assign_ok == 0);

      assert(result_assign ==
             product_lookup_table_2_bits_encrypted_mul(result_non_assign, right_val));

      shortint_destroy_ciphertext(ct_left);
      shortint_destroy_ciphertext(ct_right);
      shortint_destroy_ciphertext(ct_out);
    }
  }

  shortint_destroy_bivariate_pbs_lookup_table(lookup_table);
  shortint_destroy_client_key(cks);
  shortint_destroy_server_key(sks);
}

int main(void) {
  test_shortint_pbs_2_bits_message();
  test_shortint_bivariate_pbs_2_bits_message();
  return EXIT_SUCCESS;
}

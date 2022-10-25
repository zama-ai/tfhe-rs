#include "tfhe.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

void test_binary_boolean_function(BooleanClientKey *cks, BooleanServerKey *sks,
                                  bool (*c_fun)(bool, bool),
                                  int (*api_fun)(const BooleanServerKey *,
                                                 const BooleanCiphertext *,
                                                 const BooleanCiphertext *, BooleanCiphertext **)) {
  for (int idx_left_trivial = 0; idx_left_trivial < 2; ++idx_left_trivial) {
    for (int idx_right_trivial = 0; idx_right_trivial < 2; ++idx_right_trivial) {
      for (int idx_left = 0; idx_left < 2; ++idx_left) {
        for (int idx_right = 0; idx_right < 2; ++idx_right) {
          BooleanCiphertext *ct_left = NULL;
          BooleanCiphertext *ct_right = NULL;
          BooleanCiphertext *ct_result = NULL;

          bool left = (bool)idx_left;
          bool right = (bool)idx_right;
          bool left_trivial = (bool)idx_left_trivial;
          bool right_trivial = (bool)idx_right_trivial;

          bool expected = c_fun(left, right);

          if (left_trivial) {
            int encrypt_left_ok = booleans_trivial_encrypt(left, &ct_left);
            assert(encrypt_left_ok == 0);
          } else {
            int encrypt_left_ok = booleans_client_key_encrypt(cks, left, &ct_left);
            assert(encrypt_left_ok == 0);
          }

          if (right_trivial) {
            int encrypt_left_ok = booleans_trivial_encrypt(right, &ct_right);
            assert(encrypt_left_ok == 0);
          } else {
            int encrypt_right_ok = booleans_client_key_encrypt(cks, right, &ct_right);
            assert(encrypt_right_ok == 0);
          }

          int api_call_ok = api_fun(sks, ct_left, ct_right, &ct_result);
          assert(api_call_ok == 0);

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
  }
}

void test_not(BooleanClientKey *cks, BooleanServerKey *sks) {
  for (int idx_in_trivial = 0; idx_in_trivial < 2; ++idx_in_trivial) {
    for (int idx_in = 0; idx_in < 2; ++idx_in) {
      BooleanCiphertext *ct_in = NULL;
      BooleanCiphertext *ct_result = NULL;

      bool in = (bool)idx_in;
      bool in_trivial = (bool)idx_in_trivial;

      bool expected = !in;

      if (in_trivial) {
        int encrypt_in_ok = booleans_trivial_encrypt(in, &ct_in);
        assert(encrypt_in_ok == 0);
      } else {
        int encrypt_in_ok = booleans_client_key_encrypt(cks, in, &ct_in);
        assert(encrypt_in_ok == 0);
      }

      int api_call_ok = booleans_server_key_not(sks, ct_in, &ct_result);
      assert(api_call_ok == 0);

      bool decrypted_result = false;

      int decrypt_ok = booleans_client_key_decrypt(cks, ct_result, &decrypted_result);
      assert(decrypt_ok == 0);

      assert(decrypted_result == expected);

      destroy_boolean_ciphertext(ct_in);
      destroy_boolean_ciphertext(ct_result);
    }
  }
}

void test_mux(BooleanClientKey *cks, BooleanServerKey *sks) {
  for (int idx_cond_trivial = 0; idx_cond_trivial < 2; ++idx_cond_trivial) {
    for (int idx_then_trivial = 0; idx_then_trivial < 2; ++idx_then_trivial) {
      for (int idx_else_trivial = 0; idx_else_trivial < 2; ++idx_else_trivial) {
        for (int idx_condition = 0; idx_condition < 2; ++idx_condition) {
          for (int idx_then = 0; idx_then < 2; ++idx_then) {
            for (int idx_else = 0; idx_else < 2; ++idx_else) {
              BooleanCiphertext *ct_cond = NULL;
              BooleanCiphertext *ct_then = NULL;
              BooleanCiphertext *ct_else = NULL;
              BooleanCiphertext *ct_result = NULL;

              bool cond = (bool)idx_else;
              bool then = (bool)idx_then;
              bool else_ = (bool)idx_else;
              bool cond_trivial = (bool)idx_cond_trivial;
              bool then_trivial = (bool)idx_then_trivial;
              bool else_trivial = (bool)idx_else_trivial;

              bool expected = else_;
              if (cond) {
                expected = then;
              }

              if (cond_trivial) {
                int encrypt_cond_ok = booleans_trivial_encrypt(cond, &ct_cond);
                assert(encrypt_cond_ok == 0);
              } else {
                int encrypt_cond_ok = booleans_client_key_encrypt(cks, cond, &ct_cond);
                assert(encrypt_cond_ok == 0);
              }
              if (then_trivial) {
                int encrypt_then_ok = booleans_trivial_encrypt(then, &ct_then);
                assert(encrypt_then_ok == 0);
              } else {
                int encrypt_then_ok = booleans_client_key_encrypt(cks, then, &ct_then);
                assert(encrypt_then_ok == 0);
              }
              if (else_trivial) {
                int encrypt_else_ok = booleans_trivial_encrypt(else_, &ct_else);
                assert(encrypt_else_ok == 0);
              } else {
                int encrypt_else_ok = booleans_client_key_encrypt(cks, else_, &ct_else);
                assert(encrypt_else_ok == 0);
              }

              int api_call_ok = booleans_server_key_mux(sks, ct_cond, ct_then, ct_else, &ct_result);
              assert(api_call_ok == 0);

              bool decrypted_result = false;

              int decrypt_ok = booleans_client_key_decrypt(cks, ct_result, &decrypted_result);
              assert(decrypt_ok == 0);

              assert(decrypted_result == expected);

              destroy_boolean_ciphertext(ct_cond);
              destroy_boolean_ciphertext(ct_then);
              destroy_boolean_ciphertext(ct_else);
              destroy_boolean_ciphertext(ct_result);
            }
          }
        }
      }
    }
  }
}

bool c_and(bool left, bool right) { return left && right; }

bool c_nand(bool left, bool right) { return !c_and(left, right); }

bool c_or(bool left, bool right) { return left || right; }

bool c_nor(bool left, bool right) { return !c_or(left, right); }

bool c_xor(bool left, bool right) { return left != right; }

bool c_xnor(bool left, bool right) { return !c_xor(left, right); }

void test_server_key(void) {
  BooleanClientKey *cks = NULL;
  BooleanServerKey *sks = NULL;

  int gen_keys_ok = booleans_gen_keys_with_default_parameters(&cks, &sks);
  assert(gen_keys_ok == 0);

  test_binary_boolean_function(cks, sks, c_and, booleans_server_key_and);
  test_binary_boolean_function(cks, sks, c_nand, booleans_server_key_nand);
  test_binary_boolean_function(cks, sks, c_or, booleans_server_key_or);
  test_binary_boolean_function(cks, sks, c_nor, booleans_server_key_nor);
  test_binary_boolean_function(cks, sks, c_xor, booleans_server_key_xor);
  test_binary_boolean_function(cks, sks, c_xnor, booleans_server_key_xnor);

  test_not(cks, sks);
  test_mux(cks, sks);

  destroy_boolean_client_key(cks);
  destroy_boolean_server_key(sks);
}

int main(void) {
  test_server_key();
  return EXIT_SUCCESS;
}

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
            int encrypt_left_ok = boolean_trivial_encrypt(left, &ct_left);
            assert(encrypt_left_ok == 0);
          } else {
            int encrypt_left_ok = boolean_client_key_encrypt(cks, left, &ct_left);
            assert(encrypt_left_ok == 0);
          }

          if (right_trivial) {
            int encrypt_left_ok = boolean_trivial_encrypt(right, &ct_right);
            assert(encrypt_left_ok == 0);
          } else {
            int encrypt_right_ok = boolean_client_key_encrypt(cks, right, &ct_right);
            assert(encrypt_right_ok == 0);
          }

          int api_call_ok = api_fun(sks, ct_left, ct_right, &ct_result);
          assert(api_call_ok == 0);

          bool decrypted_result = false;

          int decrypt_ok = boolean_client_key_decrypt(cks, ct_result, &decrypted_result);
          assert(decrypt_ok == 0);

          assert(decrypted_result == expected);

          boolean_destroy_ciphertext(ct_left);
          boolean_destroy_ciphertext(ct_right);
          boolean_destroy_ciphertext(ct_result);
        }
      }
    }
  }
}

void test_binary_boolean_function_assign(
    BooleanClientKey *cks, BooleanServerKey *sks, bool (*c_fun)(bool, bool),
    int (*api_fun)(const BooleanServerKey *, BooleanCiphertext *, const BooleanCiphertext *)) {
  for (int idx_left_trivial = 0; idx_left_trivial < 2; ++idx_left_trivial) {
    for (int idx_right_trivial = 0; idx_right_trivial < 2; ++idx_right_trivial) {
      for (int idx_left = 0; idx_left < 2; ++idx_left) {
        for (int idx_right = 0; idx_right < 2; ++idx_right) {
          BooleanCiphertext *ct_left_and_result = NULL;
          BooleanCiphertext *ct_right = NULL;

          bool left = (bool)idx_left;
          bool right = (bool)idx_right;
          bool left_trivial = (bool)idx_left_trivial;
          bool right_trivial = (bool)idx_right_trivial;

          bool expected = c_fun(left, right);

          if (left_trivial) {
            int encrypt_left_ok = boolean_trivial_encrypt(left, &ct_left_and_result);
            assert(encrypt_left_ok == 0);
          } else {
            int encrypt_left_ok = boolean_client_key_encrypt(cks, left, &ct_left_and_result);
            assert(encrypt_left_ok == 0);
          }

          if (right_trivial) {
            int encrypt_left_ok = boolean_trivial_encrypt(right, &ct_right);
            assert(encrypt_left_ok == 0);
          } else {
            int encrypt_right_ok = boolean_client_key_encrypt(cks, right, &ct_right);
            assert(encrypt_right_ok == 0);
          }

          int api_call_ok = api_fun(sks, ct_left_and_result, ct_right);
          assert(api_call_ok == 0);

          bool decrypted_result = false;

          int decrypt_ok = boolean_client_key_decrypt(cks, ct_left_and_result, &decrypted_result);
          assert(decrypt_ok == 0);

          assert(decrypted_result == expected);

          boolean_destroy_ciphertext(ct_left_and_result);
          boolean_destroy_ciphertext(ct_right);
        }
      }
    }
  }
}

void test_binary_boolean_function_scalar(BooleanClientKey *cks, BooleanServerKey *sks,
                                         bool (*c_fun)(bool, bool),
                                         int (*api_fun)(const BooleanServerKey *,
                                                        const BooleanCiphertext *, bool,
                                                        BooleanCiphertext **)) {
  for (int idx_left = 0; idx_left < 2; ++idx_left) {
    for (int idx_right = 0; idx_right < 2; ++idx_right) {
      BooleanCiphertext *ct_left = NULL;
      BooleanCiphertext *ct_result = NULL;

      bool left = (bool)idx_left;
      bool right = (bool)idx_right;

      bool expected = c_fun(left, right);

      int encrypt_left_ok = boolean_client_key_encrypt(cks, left, &ct_left);
      assert(encrypt_left_ok == 0);

      int api_call_ok = api_fun(sks, ct_left, right, &ct_result);
      assert(api_call_ok == 0);

      bool decrypted_result = false;

      int decrypt_ok = boolean_client_key_decrypt(cks, ct_result, &decrypted_result);
      assert(decrypt_ok == 0);

      assert(decrypted_result == expected);

      boolean_destroy_ciphertext(ct_left);
      boolean_destroy_ciphertext(ct_result);
    }
  }
}

void test_binary_boolean_function_scalar_assign(BooleanClientKey *cks, BooleanServerKey *sks,
                                                bool (*c_fun)(bool, bool),
                                                int (*api_fun)(const BooleanServerKey *,
                                                               BooleanCiphertext *, bool)) {
  for (int idx_left = 0; idx_left < 2; ++idx_left) {
    for (int idx_right = 0; idx_right < 2; ++idx_right) {
      BooleanCiphertext *ct_left_and_result = NULL;

      bool left = (bool)idx_left;
      bool right = (bool)idx_right;

      bool expected = c_fun(left, right);

      int encrypt_left_ok = boolean_client_key_encrypt(cks, left, &ct_left_and_result);
      assert(encrypt_left_ok == 0);

      int api_call_ok = api_fun(sks, ct_left_and_result, right);
      assert(api_call_ok == 0);

      bool decrypted_result = false;

      int decrypt_ok = boolean_client_key_decrypt(cks, ct_left_and_result, &decrypted_result);
      assert(decrypt_ok == 0);

      assert(decrypted_result == expected);

      boolean_destroy_ciphertext(ct_left_and_result);
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
        int encrypt_in_ok = boolean_trivial_encrypt(in, &ct_in);
        assert(encrypt_in_ok == 0);
      } else {
        int encrypt_in_ok = boolean_client_key_encrypt(cks, in, &ct_in);
        assert(encrypt_in_ok == 0);
      }

      int api_call_ok = boolean_server_key_not(sks, ct_in, &ct_result);
      assert(api_call_ok == 0);

      bool decrypted_result = false;

      int decrypt_ok = boolean_client_key_decrypt(cks, ct_result, &decrypted_result);
      assert(decrypt_ok == 0);

      assert(decrypted_result == expected);

      boolean_destroy_ciphertext(ct_in);
      boolean_destroy_ciphertext(ct_result);
    }
  }
}

void test_not_assign(BooleanClientKey *cks, BooleanServerKey *sks) {
  for (int idx_in_trivial = 0; idx_in_trivial < 2; ++idx_in_trivial) {
    for (int idx_in = 0; idx_in < 2; ++idx_in) {
      BooleanCiphertext *ct_in_and_result = NULL;

      bool in = (bool)idx_in;
      bool in_trivial = (bool)idx_in_trivial;

      bool expected = !in;

      if (in_trivial) {
        int encrypt_in_ok = boolean_trivial_encrypt(in, &ct_in_and_result);
        assert(encrypt_in_ok == 0);
      } else {
        int encrypt_in_ok = boolean_client_key_encrypt(cks, in, &ct_in_and_result);
        assert(encrypt_in_ok == 0);
      }

      int api_call_ok = boolean_server_key_not_assign(sks, ct_in_and_result);
      assert(api_call_ok == 0);

      bool decrypted_result = false;

      int decrypt_ok = boolean_client_key_decrypt(cks, ct_in_and_result, &decrypted_result);
      assert(decrypt_ok == 0);

      assert(decrypted_result == expected);

      boolean_destroy_ciphertext(ct_in_and_result);
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
                int encrypt_cond_ok = boolean_trivial_encrypt(cond, &ct_cond);
                assert(encrypt_cond_ok == 0);
              } else {
                int encrypt_cond_ok = boolean_client_key_encrypt(cks, cond, &ct_cond);
                assert(encrypt_cond_ok == 0);
              }
              if (then_trivial) {
                int encrypt_then_ok = boolean_trivial_encrypt(then, &ct_then);
                assert(encrypt_then_ok == 0);
              } else {
                int encrypt_then_ok = boolean_client_key_encrypt(cks, then, &ct_then);
                assert(encrypt_then_ok == 0);
              }
              if (else_trivial) {
                int encrypt_else_ok = boolean_trivial_encrypt(else_, &ct_else);
                assert(encrypt_else_ok == 0);
              } else {
                int encrypt_else_ok = boolean_client_key_encrypt(cks, else_, &ct_else);
                assert(encrypt_else_ok == 0);
              }

              int api_call_ok = boolean_server_key_mux(sks, ct_cond, ct_then, ct_else, &ct_result);
              assert(api_call_ok == 0);

              bool decrypted_result = false;

              int decrypt_ok = boolean_client_key_decrypt(cks, ct_result, &decrypted_result);
              assert(decrypt_ok == 0);

              assert(decrypted_result == expected);

              boolean_destroy_ciphertext(ct_cond);
              boolean_destroy_ciphertext(ct_then);
              boolean_destroy_ciphertext(ct_else);
              boolean_destroy_ciphertext(ct_result);
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
  BooleanCompressedServerKey *csks = NULL;
  BooleanServerKey *sks = NULL;
  DynamicBuffer cks_ser_buffer = {.pointer = NULL, .length = 0, .destructor = NULL};
  BooleanClientKey *deser_cks = NULL;
  DynamicBuffer csks_ser_buffer = {.pointer = NULL, .length = 0, .destructor = NULL};
  BooleanCompressedServerKey *deser_csks = NULL;
  DynamicBuffer sks_ser_buffer = {.pointer = NULL, .length = 0, .destructor = NULL};
  BooleanServerKey *deser_sks = NULL;

  int gen_cks_ok = boolean_gen_client_key(BOOLEAN_PARAMETERS_SET_DEFAULT_PARAMETERS, &cks);
  assert(gen_cks_ok == 0);

  int gen_csks_ok = boolean_gen_compressed_server_key(cks, &csks);
  assert(gen_csks_ok == 0);

  int ser_csks_ok = boolean_serialize_compressed_server_key(csks, &csks_ser_buffer);
  assert(ser_csks_ok == 0);

  DynamicBufferView deser_view = {.pointer = csks_ser_buffer.pointer,
                                  .length = csks_ser_buffer.length};

  int deser_csks_ok = boolean_deserialize_compressed_server_key(deser_view, &deser_csks);
  assert(deser_csks_ok == 0);

  int decompress_csks_ok = boolean_decompress_server_key(deser_csks, &sks);
  assert(decompress_csks_ok == 0);

  int ser_cks_ok = boolean_serialize_client_key(cks, &cks_ser_buffer);
  assert(ser_cks_ok == 0);

  deser_view.pointer = cks_ser_buffer.pointer;
  deser_view.length = cks_ser_buffer.length;

  int deser_cks_ok = boolean_deserialize_client_key(deser_view, &deser_cks);
  assert(deser_cks_ok == 0);

  int ser_sks_ok = boolean_serialize_server_key(sks, &sks_ser_buffer);
  assert(ser_sks_ok == 0);

  deser_view.pointer = sks_ser_buffer.pointer;
  deser_view.length = sks_ser_buffer.length;

  int deser_sks_ok = boolean_deserialize_server_key(deser_view, &deser_sks);
  assert(deser_sks_ok == 0);

  test_binary_boolean_function(deser_cks, deser_sks, c_and, boolean_server_key_and);
  test_binary_boolean_function(deser_cks, deser_sks, c_nand, boolean_server_key_nand);
  test_binary_boolean_function(deser_cks, deser_sks, c_or, boolean_server_key_or);
  test_binary_boolean_function(deser_cks, deser_sks, c_nor, boolean_server_key_nor);
  test_binary_boolean_function(deser_cks, deser_sks, c_xor, boolean_server_key_xor);
  test_binary_boolean_function(deser_cks, deser_sks, c_xnor, boolean_server_key_xnor);
  test_not(deser_cks, deser_sks);
  test_mux(deser_cks, deser_sks);

  test_binary_boolean_function_assign(deser_cks, deser_sks, c_and, boolean_server_key_and_assign);
  test_binary_boolean_function_assign(deser_cks, deser_sks, c_nand, boolean_server_key_nand_assign);
  test_binary_boolean_function_assign(deser_cks, deser_sks, c_or, boolean_server_key_or_assign);
  test_binary_boolean_function_assign(deser_cks, deser_sks, c_nor, boolean_server_key_nor_assign);
  test_binary_boolean_function_assign(deser_cks, deser_sks, c_xor, boolean_server_key_xor_assign);
  test_binary_boolean_function_assign(deser_cks, deser_sks, c_xnor, boolean_server_key_xnor_assign);
  test_not_assign(deser_cks, deser_sks);

  test_binary_boolean_function_scalar(deser_cks, deser_sks, c_and, boolean_server_key_and_scalar);
  test_binary_boolean_function_scalar(deser_cks, deser_sks, c_nand, boolean_server_key_nand_scalar);
  test_binary_boolean_function_scalar(deser_cks, deser_sks, c_or, boolean_server_key_or_scalar);
  test_binary_boolean_function_scalar(deser_cks, deser_sks, c_nor, boolean_server_key_nor_scalar);
  test_binary_boolean_function_scalar(deser_cks, deser_sks, c_xor, boolean_server_key_xor_scalar);
  test_binary_boolean_function_scalar(deser_cks, deser_sks, c_xnor, boolean_server_key_xnor_scalar);

  test_binary_boolean_function_scalar_assign(deser_cks, deser_sks, c_and,
                                             boolean_server_key_and_scalar_assign);
  test_binary_boolean_function_scalar_assign(deser_cks, deser_sks, c_nand,
                                             boolean_server_key_nand_scalar_assign);
  test_binary_boolean_function_scalar_assign(deser_cks, deser_sks, c_or,
                                             boolean_server_key_or_scalar_assign);
  test_binary_boolean_function_scalar_assign(deser_cks, deser_sks, c_nor,
                                             boolean_server_key_nor_scalar_assign);
  test_binary_boolean_function_scalar_assign(deser_cks, deser_sks, c_xor,
                                             boolean_server_key_xor_scalar_assign);
  test_binary_boolean_function_scalar_assign(deser_cks, deser_sks, c_xnor,
                                             boolean_server_key_xnor_scalar_assign);

  boolean_destroy_client_key(cks);
  boolean_destroy_compressed_server_key(csks);
  boolean_destroy_server_key(sks);
  boolean_destroy_client_key(deser_cks);
  boolean_destroy_compressed_server_key(deser_csks);
  boolean_destroy_server_key(deser_sks);
  destroy_dynamic_buffer(&cks_ser_buffer);
  destroy_dynamic_buffer(&csks_ser_buffer);
  destroy_dynamic_buffer(&sks_ser_buffer);
}

int main(void) {
  test_server_key();
  return EXIT_SUCCESS;
}

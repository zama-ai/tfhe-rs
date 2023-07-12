#include "tfhe.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

typedef int (*BinaryCallback)(const ShortintServerKey *, ShortintCiphertext *, ShortintCiphertext *,
                              ShortintCiphertext **);

typedef int (*BinaryAssignCallback)(const ShortintServerKey *, ShortintCiphertext *,
                                    ShortintCiphertext *);

typedef int (*BinaryScalarCallback)(const ShortintServerKey *, ShortintCiphertext *, uint8_t,
                                    ShortintCiphertext **);

typedef int (*UnaryCallback)(const ShortintServerKey *, ShortintCiphertext *,
                             ShortintCiphertext **);

typedef int (*UnaryAssignCallback)(const ShortintServerKey *, ShortintCiphertext *);

void test_shortint_unary_op(const ShortintClientKey *cks, const ShortintServerKey *sks,
                            const ShortintClientKey *cks_small, const ShortintServerKey *sks_small,
                            const uint32_t message_bits, uint64_t (*c_fun)(uint64_t),
                            UnaryCallback api_fun) {

  int message_max = 1 << message_bits;

  for (int is_big = 0; is_big < 2; ++is_big) {
    for (int val_in = 0; val_in < message_max; ++val_in) {
      ShortintCiphertext *ct_in = NULL;
      ShortintCiphertext *ct_result = NULL;
      const ShortintClientKey *cks_in_use = NULL;
      const ShortintServerKey *sks_in_use = NULL;

      uint64_t in = (uint64_t)val_in;

      uint64_t expected = c_fun(in) % message_max;

      if (is_big == 1) {
        cks_in_use = cks;
        sks_in_use = sks;

        int encrypt_left_ok = shortint_client_key_encrypt(cks_in_use, in, &ct_in);
        assert(encrypt_left_ok == 0);
      } else {
        cks_in_use = cks_small;
        sks_in_use = sks_small;

        int encrypt_left_ok = shortint_client_key_encrypt(cks_in_use, in, &ct_in);
        assert(encrypt_left_ok == 0);
      }

      int api_call_ok = api_fun(sks_in_use, ct_in, &ct_result);
      assert(api_call_ok == 0);

      uint64_t decrypted_result = -1;

      int decrypt_ok = shortint_client_key_decrypt(cks_in_use, ct_result, &decrypted_result);
      assert(decrypt_ok == 0);

      assert(decrypted_result == expected);

      shortint_destroy_ciphertext(ct_in);
      shortint_destroy_ciphertext(ct_result);
    }
  }
}

void test_shortint_unary_op_assign(const ShortintClientKey *cks, const ShortintServerKey *sks,
                                   const ShortintClientKey *cks_small,
                                   const ShortintServerKey *sks_small, const uint32_t message_bits,
                                   uint64_t (*c_fun)(uint64_t), UnaryAssignCallback api_fun) {

  int message_max = 1 << message_bits;

  for (int is_big = 0; is_big < 2; ++is_big) {
    for (int in = 0; in < message_max; ++in) {
      ShortintCiphertext *ct_in_and_result = NULL;
      const ShortintClientKey *cks_in_use = NULL;
      const ShortintServerKey *sks_in_use = NULL;

      uint64_t in = (uint64_t)in;

      uint64_t expected = c_fun(in) % message_max;

      if (is_big == 1) {
        cks_in_use = cks;
        sks_in_use = sks;

        int encrypt_left_ok = shortint_client_key_encrypt(cks_in_use, in, &ct_in_and_result);
        assert(encrypt_left_ok == 0);
      } else {
        cks_in_use = cks_small;
        sks_in_use = sks_small;

        int encrypt_left_ok = shortint_client_key_encrypt(cks_in_use, in, &ct_in_and_result);
        assert(encrypt_left_ok == 0);
      }

      int api_call_ok = api_fun(sks_in_use, ct_in_and_result);
      assert(api_call_ok == 0);

      uint64_t decrypted_result = -1;

      int decrypt_ok = shortint_client_key_decrypt(cks_in_use, ct_in_and_result, &decrypted_result);
      assert(decrypt_ok == 0);

      assert(decrypted_result == expected);

      shortint_destroy_ciphertext(ct_in_and_result);
    }
  }
}

void test_shortint_binary_op(const ShortintClientKey *cks, const ShortintServerKey *sks,
                             const ShortintClientKey *cks_small, const ShortintServerKey *sks_small,
                             const uint32_t message_bits, uint64_t (*c_fun)(uint64_t, uint64_t),
                             BinaryCallback api_fun) {

  int message_max = 1 << message_bits;

  for (int is_big = 0; is_big < 2; ++is_big) {
    for (int val_left = 0; val_left < message_max; ++val_left) {
      for (int val_right = 0; val_right < message_max; ++val_right) {
        ShortintCiphertext *ct_left = NULL;
        ShortintCiphertext *ct_right = NULL;
        ShortintCiphertext *ct_result = NULL;
        const ShortintClientKey *cks_in_use = NULL;
        const ShortintServerKey *sks_in_use = NULL;

        uint64_t left = (uint64_t)val_left;
        uint64_t right = (uint64_t)val_right;

        uint64_t expected = c_fun(left, right) % message_max;

        if (is_big == 1) {
          cks_in_use = cks;
          sks_in_use = sks;

          int encrypt_left_ok = shortint_client_key_encrypt(cks_in_use, left, &ct_left);
          assert(encrypt_left_ok == 0);

          int encrypt_right_ok = shortint_client_key_encrypt(cks_in_use, right, &ct_right);
          assert(encrypt_right_ok == 0);
        } else {
          cks_in_use = cks_small;
          sks_in_use = sks_small;

          int encrypt_left_ok = shortint_client_key_encrypt(cks_in_use, left, &ct_left);
          assert(encrypt_left_ok == 0);

          int encrypt_right_ok = shortint_client_key_encrypt(cks_in_use, right, &ct_right);
          assert(encrypt_right_ok == 0);
        }

        int api_call_ok = api_fun(sks_in_use, ct_left, ct_right, &ct_result);
        assert(api_call_ok == 0);

        uint64_t decrypted_result = -1;

        int decrypt_ok = shortint_client_key_decrypt(cks_in_use, ct_result, &decrypted_result);
        assert(decrypt_ok == 0);

        assert(decrypted_result == expected);

        shortint_destroy_ciphertext(ct_left);
        shortint_destroy_ciphertext(ct_right);
        shortint_destroy_ciphertext(ct_result);
      }
    }
  }
}

void test_shortint_binary_op_assign(const ShortintClientKey *cks, const ShortintServerKey *sks,
                                    const ShortintClientKey *cks_small,
                                    const ShortintServerKey *sks_small, const uint32_t message_bits,

                                    uint64_t (*c_fun)(uint64_t, uint64_t),
                                    BinaryAssignCallback api_fun) {

  int message_max = 1 << message_bits;

  for (int is_big = 0; is_big < 2; ++is_big) {
    for (int val_left = 0; val_left < message_max; ++val_left) {
      for (int val_right = 0; val_right < message_max; ++val_right) {
        ShortintCiphertext *ct_left_and_result = NULL;
        ShortintCiphertext *ct_right = NULL;
        const ShortintClientKey *cks_in_use = NULL;
        const ShortintServerKey *sks_in_use = NULL;

        uint64_t left = (uint64_t)val_left;
        uint64_t right = (uint64_t)val_right;

        uint64_t expected = c_fun(left, right) % message_max;

        if (is_big == 1) {
          cks_in_use = cks;
          sks_in_use = sks;

          int encrypt_left_ok = shortint_client_key_encrypt(cks_in_use, left, &ct_left_and_result);
          assert(encrypt_left_ok == 0);

          int encrypt_right_ok = shortint_client_key_encrypt(cks_in_use, right, &ct_right);
          assert(encrypt_right_ok == 0);
        } else {
          cks_in_use = cks_small;
          sks_in_use = sks_small;

          int encrypt_left_ok = shortint_client_key_encrypt(cks_in_use, left, &ct_left_and_result);
          assert(encrypt_left_ok == 0);

          int encrypt_right_ok = shortint_client_key_encrypt(cks_in_use, right, &ct_right);
          assert(encrypt_right_ok == 0);
        }

        int api_call_ok = api_fun(sks_in_use, ct_left_and_result, ct_right);
        assert(api_call_ok == 0);

        uint64_t decrypted_result = -1;

        int decrypt_ok =
            shortint_client_key_decrypt(cks_in_use, ct_left_and_result, &decrypted_result);
        assert(decrypt_ok == 0);

        assert(decrypted_result == expected);

        shortint_destroy_ciphertext(ct_left_and_result);
        shortint_destroy_ciphertext(ct_right);
      }
    }
  }
}

uint64_t homomorphic_div(uint64_t left, uint64_t right, uint64_t value_on_div_by_zero) {
  if (right != 0) {
    return left / right;
  } else {
    // Special value chosen in the shortint implementation in case of a division by 0
    return value_on_div_by_zero;
  }
}

void test_shortint_div(const ShortintClientKey *cks, const ShortintServerKey *sks,
                       const ShortintClientKey *cks_small, const ShortintServerKey *sks_small,
                       const uint32_t message_bits) {

  int message_max = 1 << message_bits;

  for (int is_big = 0; is_big < 2; ++is_big) {
    for (int val_left = 0; val_left < message_max; ++val_left) {
      for (int val_right = 0; val_right < message_max; ++val_right) {
        ShortintCiphertext *ct_left = NULL;
        ShortintCiphertext *ct_right = NULL;
        ShortintCiphertext *ct_result = NULL;
        const ShortintClientKey *cks_in_use = NULL;
        const ShortintServerKey *sks_in_use = NULL;

        uint64_t left = (uint64_t)val_left;
        uint64_t right = (uint64_t)val_right;

        uint64_t expected = homomorphic_div(left, right, (uint64_t)(message_max - 1)) % message_max;

        if (is_big == 1) {
          cks_in_use = cks;
          sks_in_use = sks;

          int encrypt_left_ok = shortint_client_key_encrypt(cks_in_use, left, &ct_left);
          assert(encrypt_left_ok == 0);

          int encrypt_right_ok = shortint_client_key_encrypt(cks_in_use, right, &ct_right);
          assert(encrypt_right_ok == 0);
        } else {
          cks_in_use = cks_small;
          sks_in_use = sks_small;

          int encrypt_left_ok = shortint_client_key_encrypt(cks_in_use, left, &ct_left);
          assert(encrypt_left_ok == 0);

          int encrypt_right_ok = shortint_client_key_encrypt(cks_in_use, right, &ct_right);
          assert(encrypt_right_ok == 0);
        }

        int api_call_ok =
            shortint_server_key_unchecked_div(sks_in_use, ct_left, ct_right, &ct_result);
        assert(api_call_ok == 0);

        uint64_t decrypted_result = -1;

        int decrypt_ok = shortint_client_key_decrypt(cks_in_use, ct_result, &decrypted_result);
        assert(decrypt_ok == 0);

        assert(decrypted_result == expected);

        shortint_destroy_ciphertext(ct_left);
        shortint_destroy_ciphertext(ct_right);
        shortint_destroy_ciphertext(ct_result);
      }
    }
  }
}

void test_shortint_div_assign(const ShortintClientKey *cks, const ShortintServerKey *sks,
                              const ShortintClientKey *cks_small,
                              const ShortintServerKey *sks_small, const uint32_t message_bits) {

  int message_max = 1 << message_bits;

  for (int is_big = 0; is_big < 2; ++is_big) {
    for (int val_left = 0; val_left < message_max; ++val_left) {
      for (int val_right = 0; val_right < message_max; ++val_right) {
        ShortintCiphertext *ct_left_and_result = NULL;
        ShortintCiphertext *ct_right = NULL;
        const ShortintClientKey *cks_in_use = NULL;
        const ShortintServerKey *sks_in_use = NULL;

        uint64_t left = (uint64_t)val_left;
        uint64_t right = (uint64_t)val_right;

        uint64_t expected = homomorphic_div(left, right, (uint64_t)(message_max - 1)) % message_max;

        if (is_big == 1) {
          cks_in_use = cks;
          sks_in_use = sks;

          int encrypt_left_ok = shortint_client_key_encrypt(cks_in_use, left, &ct_left_and_result);
          assert(encrypt_left_ok == 0);

          int encrypt_right_ok = shortint_client_key_encrypt(cks_in_use, right, &ct_right);
          assert(encrypt_right_ok == 0);
        } else {
          cks_in_use = cks_small;
          sks_in_use = sks_small;

          int encrypt_left_ok = shortint_client_key_encrypt(cks_in_use, left, &ct_left_and_result);
          assert(encrypt_left_ok == 0);

          int encrypt_right_ok = shortint_client_key_encrypt(cks_in_use, right, &ct_right);
          assert(encrypt_right_ok == 0);
        }

        int api_call_ok =
            shortint_server_key_unchecked_div_assign(sks_in_use, ct_left_and_result, ct_right);
        assert(api_call_ok == 0);

        uint64_t decrypted_result = -1;

        int decrypt_ok =
            shortint_client_key_decrypt(cks_in_use, ct_left_and_result, &decrypted_result);
        assert(decrypt_ok == 0);

        assert(decrypted_result == expected);

        shortint_destroy_ciphertext(ct_left_and_result);
        shortint_destroy_ciphertext(ct_right);
      }
    }
  }
}

void test_shortint_binary_scalar_op(
    const ShortintClientKey *cks, const ShortintServerKey *sks, const ShortintClientKey *cks_small,
    const ShortintServerKey *sks_small, const uint32_t message_bits,
    uint64_t (*c_fun)(uint64_t, uint8_t),
    int (*api_fun)(const ShortintServerKey *, ShortintCiphertext *, uint8_t, ShortintCiphertext **),
    uint8_t forbidden_scalar_values[], size_t forbidden_scalar_values_len) {

  int message_max = 1 << message_bits;

  for (int is_big = 0; is_big < 2; ++is_big) {
    for (int val_left = 0; val_left < message_max; ++val_left) {
      for (int val_right = 0; val_right < message_max; ++val_right) {
        ShortintCiphertext *ct_left = NULL;
        ShortintCiphertext *ct_result = NULL;
        const ShortintClientKey *cks_in_use = NULL;
        const ShortintServerKey *sks_in_use = NULL;

        uint64_t left = (uint64_t)val_left;
        uint8_t scalar_right = (uint8_t)val_right;

        if (forbidden_scalar_values != NULL) {
          bool found_forbidden_value = false;
          for (int idx = 0; idx < forbidden_scalar_values_len; ++idx) {
            if (forbidden_scalar_values[idx] == scalar_right) {
              found_forbidden_value = true;
              break;
            }
          }

          if (found_forbidden_value) {
            continue;
          }
        }

        uint64_t expected = c_fun(left, scalar_right) % message_max;

        if (is_big == 1) {
          cks_in_use = cks;
          sks_in_use = sks;

          int encrypt_left_ok = shortint_client_key_encrypt(cks_in_use, left, &ct_left);
          assert(encrypt_left_ok == 0);
        } else {
          cks_in_use = cks_small;
          sks_in_use = sks_small;

          int encrypt_left_ok = shortint_client_key_encrypt(cks_in_use, left, &ct_left);
          assert(encrypt_left_ok == 0);
        }

        int api_call_ok = api_fun(sks_in_use, ct_left, scalar_right, &ct_result);
        assert(api_call_ok == 0);

        uint64_t decrypted_result = -1;

        int decrypt_ok = shortint_client_key_decrypt(cks_in_use, ct_result, &decrypted_result);
        assert(decrypt_ok == 0);

        assert(decrypted_result == expected);

        shortint_destroy_ciphertext(ct_left);
        shortint_destroy_ciphertext(ct_result);
      }
    }
  }
}

void test_shortint_binary_scalar_op_assign(
    const ShortintClientKey *cks, const ShortintServerKey *sks, const ShortintClientKey *cks_small,
    const ShortintServerKey *sks_small, const uint32_t message_bits,
    uint64_t (*c_fun)(uint64_t, uint8_t),
    int (*api_fun)(const ShortintServerKey *, ShortintCiphertext *, uint8_t),
    uint8_t forbidden_scalar_values[], size_t forbidden_scalar_values_len) {

  int message_max = 1 << message_bits;

  for (int is_big = 0; is_big < 2; ++is_big) {
    for (int val_left = 0; val_left < message_max; ++val_left) {
      for (int val_right = 0; val_right < message_max; ++val_right) {
        ShortintCiphertext *ct_left_and_result = NULL;
        const ShortintClientKey *cks_in_use = NULL;
        const ShortintServerKey *sks_in_use = NULL;

        uint64_t left = (uint64_t)val_left;
        uint8_t scalar_right = (uint8_t)val_right;

        if (forbidden_scalar_values != NULL) {
          bool found_forbidden_value = false;
          for (int idx = 0; idx < forbidden_scalar_values_len; ++idx) {
            if (forbidden_scalar_values[idx] == scalar_right) {
              found_forbidden_value = true;
              break;
            }
          }

          if (found_forbidden_value) {
            continue;
          }
        }

        uint64_t expected = c_fun(left, scalar_right) % message_max;

        if (is_big == 1) {
          cks_in_use = cks;
          sks_in_use = sks;

          int encrypt_left_ok = shortint_client_key_encrypt(cks_in_use, left, &ct_left_and_result);
          assert(encrypt_left_ok == 0);
        } else {
          cks_in_use = cks_small;
          sks_in_use = sks_small;

          int encrypt_left_ok = shortint_client_key_encrypt(cks_in_use, left, &ct_left_and_result);
          assert(encrypt_left_ok == 0);
        }

        int api_call_ok = api_fun(sks_in_use, ct_left_and_result, scalar_right);
        assert(api_call_ok == 0);

        uint64_t decrypted_result = -1;

        int decrypt_ok =
            shortint_client_key_decrypt(cks_in_use, ct_left_and_result, &decrypted_result);
        assert(decrypt_ok == 0);

        assert(decrypted_result == expected);

        shortint_destroy_ciphertext(ct_left_and_result);
      }
    }
  }
}

uint64_t add(uint64_t left, uint64_t right) { return left + right; }
uint64_t sub(uint64_t left, uint64_t right) { return left - right; }
uint64_t mul(uint64_t left, uint64_t right) { return left * right; }
uint64_t neg(uint64_t in) { return -in; }

uint64_t bitand(uint64_t left, uint64_t right) { return left & right; }
uint64_t bitxor(uint64_t left, uint64_t right) { return left ^ right; }
uint64_t bitor (uint64_t left, uint64_t right) { return left | right; }

uint64_t greater(uint64_t left, uint64_t right) { return (uint64_t)(left > right); }
uint64_t greater_or_equal(uint64_t left, uint64_t right) { return (uint64_t)(left >= right); }
uint64_t less(uint64_t left, uint64_t right) { return (uint64_t)(left < right); }
uint64_t less_or_equal(uint64_t left, uint64_t right) { return (uint64_t)(left <= right); }
uint64_t equal(uint64_t left, uint64_t right) { return (uint64_t)(left == right); }
uint64_t not_equal(uint64_t left, uint64_t right) { return (uint64_t)(left != right); }

uint64_t scalar_greater(uint64_t left, uint8_t right) { return (uint64_t)(left > right); }
uint64_t scalar_greater_or_equal(uint64_t left, uint8_t right) { return (uint64_t)(left >= right); }
uint64_t scalar_less(uint64_t left, uint8_t right) { return (uint64_t)(left < right); }
uint64_t scalar_less_or_equal(uint64_t left, uint8_t right) { return (uint64_t)(left <= right); }
uint64_t scalar_equal(uint64_t left, uint8_t right) { return (uint64_t)(left == right); }
uint64_t scalar_not_equal(uint64_t left, uint8_t right) { return (uint64_t)(left != right); }

uint64_t scalar_add(uint64_t left, uint8_t right) { return left + right; }
uint64_t scalar_sub(uint64_t left, uint8_t right) { return left - right; }
uint64_t scalar_mul(uint64_t left, uint8_t right) { return left * right; }
uint64_t scalar_div(uint64_t left, uint8_t right) { return left / right; }
uint64_t scalar_mod(uint64_t left, uint8_t right) { return left % right; }

uint64_t left_shift(uint64_t left, uint8_t right) { return left << right; }
uint64_t right_shift(uint64_t left, uint8_t right) { return left >> right; }

void test_server_key(void) {
  ShortintClientKey *cks = NULL;
  ShortintCompressedServerKey *csks = NULL;
  ShortintServerKey *sks = NULL;
  Buffer cks_ser_buffer = {.pointer = NULL, .length = 0};
  ShortintClientKey *deser_cks = NULL;
  Buffer csks_ser_buffer = {.pointer = NULL, .length = 0};
  ShortintCompressedServerKey *deser_csks = NULL;
  Buffer sks_ser_buffer = {.pointer = NULL, .length = 0};
  ShortintServerKey *deser_sks = NULL;
  ShortintClientKey *cks_small = NULL;
  ShortintServerKey *sks_small = NULL;
  ShortintPBSParameters params = {0};
  ShortintPBSParameters params_small = {0};

  const uint32_t message_bits = 2;
  const uint32_t carry_bits = 2;

  int get_params_ok = shortint_get_parameters(message_bits, carry_bits, &params);
  assert(get_params_ok == 0);

  int get_params_small_ok = shortint_get_parameters_small(message_bits, carry_bits, &params_small);
  assert(get_params_small_ok == 0);

  int gen_cks_ok = shortint_gen_client_key(params, &cks);
  assert(gen_cks_ok == 0);

  int gen_cks_small_ok = shortint_gen_client_key(params_small, &cks_small);
  assert(gen_cks_small_ok == 0);

  int gen_sks_small_ok = shortint_gen_server_key(cks_small, &sks_small);
  assert(gen_sks_small_ok == 0);

  int gen_csks_ok = shortint_gen_compressed_server_key(cks, &csks);
  assert(gen_csks_ok == 0);

  int ser_csks_ok = shortint_serialize_compressed_server_key(csks, &csks_ser_buffer);
  assert(ser_csks_ok == 0);

  BufferView deser_view = {.pointer = csks_ser_buffer.pointer, .length = csks_ser_buffer.length};

  int deser_csks_ok = shortint_deserialize_compressed_server_key(deser_view, &deser_csks);
  assert(deser_csks_ok == 0);

  int decompress_csks_ok = shortint_decompress_server_key(deser_csks, &sks);
  assert(decompress_csks_ok == 0);

  int ser_cks_ok = shortint_serialize_client_key(cks, &cks_ser_buffer);
  assert(ser_cks_ok == 0);

  deser_view.pointer = cks_ser_buffer.pointer;
  deser_view.length = cks_ser_buffer.length;

  int deser_cks_ok = shortint_deserialize_client_key(deser_view, &deser_cks);
  assert(deser_cks_ok == 0);

  int ser_sks_ok = shortint_serialize_server_key(sks, &sks_ser_buffer);
  assert(ser_sks_ok == 0);

  deser_view.pointer = sks_ser_buffer.pointer;
  deser_view.length = sks_ser_buffer.length;

  int deser_sks_ok = shortint_deserialize_server_key(deser_view, &deser_sks);
  assert(deser_sks_ok == 0);

  printf("add\n");
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, add,
                          (BinaryCallback)shortint_server_key_smart_add);
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, add,
                          (BinaryCallback)shortint_server_key_unchecked_add);
  test_shortint_binary_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits, add,
                                 (BinaryAssignCallback)shortint_server_key_smart_add_assign);
  test_shortint_binary_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits, add,
                                 (BinaryAssignCallback)shortint_server_key_unchecked_add_assign);

  printf("sub\n");
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, sub,
                          (BinaryCallback)shortint_server_key_smart_sub);
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, sub,
                          (BinaryCallback)shortint_server_key_unchecked_sub);
  test_shortint_binary_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits, sub,
                                 (BinaryAssignCallback)shortint_server_key_smart_sub_assign);
  test_shortint_binary_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits, sub,
                                 (BinaryAssignCallback)shortint_server_key_unchecked_sub_assign);

  printf("mul\n");
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, mul,
                          (BinaryCallback)shortint_server_key_smart_mul);
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, mul,
                          (BinaryCallback)shortint_server_key_unchecked_mul);
  test_shortint_binary_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits, mul,
                                 (BinaryAssignCallback)shortint_server_key_smart_mul_assign);
  test_shortint_binary_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits, mul,
                                 (BinaryAssignCallback)shortint_server_key_unchecked_mul_assign);

  printf("left_shift\n");
  test_shortint_binary_scalar_op(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, left_shift,
      (BinaryScalarCallback)shortint_server_key_smart_scalar_left_shift, NULL, 0);
  test_shortint_binary_scalar_op(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, left_shift,
      (BinaryScalarCallback)shortint_server_key_unchecked_scalar_left_shift, NULL, 0);
  test_shortint_binary_scalar_op_assign(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, left_shift,
      shortint_server_key_smart_scalar_left_shift_assign, NULL, 0);
  test_shortint_binary_scalar_op_assign(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, left_shift,
      shortint_server_key_unchecked_scalar_left_shift_assign, NULL, 0);

  printf("right_shift\n");
  test_shortint_binary_scalar_op(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, right_shift,
      (BinaryScalarCallback)shortint_server_key_smart_scalar_right_shift, NULL, 0);
  test_shortint_binary_scalar_op(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, right_shift,
      (BinaryScalarCallback)shortint_server_key_unchecked_scalar_right_shift, NULL, 0);
  test_shortint_binary_scalar_op_assign(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, right_shift,
      shortint_server_key_smart_scalar_right_shift_assign, NULL, 0);
  test_shortint_binary_scalar_op_assign(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, right_shift,
      shortint_server_key_unchecked_scalar_right_shift_assign, NULL, 0);

  printf("scalar_add\n");
  test_shortint_binary_scalar_op(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, scalar_add,
      (BinaryScalarCallback)shortint_server_key_smart_scalar_add, NULL, 0);
  test_shortint_binary_scalar_op(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, scalar_add,
      (BinaryScalarCallback)shortint_server_key_unchecked_scalar_add, NULL, 0);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits,
                                        scalar_add, shortint_server_key_smart_scalar_add_assign,
                                        NULL, 0);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits,
                                        scalar_add, shortint_server_key_unchecked_scalar_add_assign,
                                        NULL, 0);

  printf("scalar_sub\n");
  test_shortint_binary_scalar_op(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, scalar_sub,
      (BinaryScalarCallback)shortint_server_key_smart_scalar_sub, NULL, 0);
  test_shortint_binary_scalar_op(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, scalar_sub,
      (BinaryScalarCallback)shortint_server_key_unchecked_scalar_sub, NULL, 0);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits,
                                        scalar_sub, shortint_server_key_smart_scalar_sub_assign,
                                        NULL, 0);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits,
                                        scalar_sub, shortint_server_key_unchecked_scalar_sub_assign,
                                        NULL, 0);

  printf("scalar_mul\n");
  test_shortint_binary_scalar_op(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, scalar_mul,
      (BinaryScalarCallback)shortint_server_key_smart_scalar_mul, NULL, 0);
  test_shortint_binary_scalar_op(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, scalar_mul,
      (BinaryScalarCallback)shortint_server_key_unchecked_scalar_mul, NULL, 0);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits,
                                        scalar_mul, shortint_server_key_smart_scalar_mul_assign,
                                        NULL, 0);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits,
                                        scalar_mul, shortint_server_key_unchecked_scalar_mul_assign,
                                        NULL, 0);

  printf("bitand\n");
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, bitand,
                          (BinaryCallback)shortint_server_key_smart_bitand);
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, bitand,
                          (BinaryCallback)shortint_server_key_unchecked_bitand);
  test_shortint_binary_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits, bitand,
                                 (BinaryAssignCallback)shortint_server_key_smart_bitand_assign);
  test_shortint_binary_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits, bitand,
                                 (BinaryAssignCallback)shortint_server_key_unchecked_bitand_assign);

  printf("bitxor\n");
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, bitxor,
                          (BinaryCallback)shortint_server_key_smart_bitxor);
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, bitxor,
                          (BinaryCallback)shortint_server_key_unchecked_bitxor);
  test_shortint_binary_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits, bitxor,
                                 (BinaryAssignCallback)shortint_server_key_smart_bitxor_assign);
  test_shortint_binary_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits, bitxor,
                                 (BinaryAssignCallback)shortint_server_key_unchecked_bitxor_assign);

  printf("bitor\n");
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, bitor,
                          (BinaryCallback)shortint_server_key_smart_bitor);
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, bitor,
                          (BinaryCallback)shortint_server_key_unchecked_bitor);
  test_shortint_binary_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits, bitor,
                                 (BinaryAssignCallback)shortint_server_key_smart_bitor_assign);
  test_shortint_binary_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits, bitor,
                                 (BinaryAssignCallback)shortint_server_key_unchecked_bitor_assign);

  printf("greater\n");
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, greater,
                          (BinaryCallback)shortint_server_key_smart_greater);
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, greater,
                          (BinaryCallback)shortint_server_key_unchecked_greater);

  printf("greater_or_equal\n");
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits,
                          greater_or_equal,
                          (BinaryCallback)shortint_server_key_smart_greater_or_equal);
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits,
                          greater_or_equal,
                          (BinaryCallback)shortint_server_key_unchecked_greater_or_equal);

  printf("less\n");
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, less,
                          (BinaryCallback)shortint_server_key_smart_less);
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, less,
                          (BinaryCallback)shortint_server_key_unchecked_less);

  printf("less_or_equal\n");
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, less_or_equal,
                          (BinaryCallback)shortint_server_key_smart_less_or_equal);
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, less_or_equal,
                          (BinaryCallback)shortint_server_key_unchecked_less_or_equal);

  printf("equal\n");
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, equal,
                          (BinaryCallback)shortint_server_key_smart_equal);
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, equal,
                          (BinaryCallback)shortint_server_key_unchecked_equal);

  printf("not_equal\n");
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, not_equal,
                          (BinaryCallback)shortint_server_key_smart_not_equal);
  test_shortint_binary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, not_equal,
                          (BinaryCallback)shortint_server_key_unchecked_not_equal);

  printf("scalar_greater\n");
  test_shortint_binary_scalar_op(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, scalar_greater,
      (BinaryScalarCallback)shortint_server_key_smart_scalar_greater, NULL, 0);

  printf("scalar_greater_or_equal\n");
  test_shortint_binary_scalar_op(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, scalar_greater_or_equal,
      (BinaryScalarCallback)shortint_server_key_smart_scalar_greater_or_equal, NULL, 0);

  printf("scalar_less\n");
  test_shortint_binary_scalar_op(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, scalar_less,
      (BinaryScalarCallback)shortint_server_key_smart_scalar_less, NULL, 0);

  printf("scalar_less_or_equal\n");
  test_shortint_binary_scalar_op(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, scalar_less_or_equal,
      (BinaryScalarCallback)shortint_server_key_smart_scalar_less_or_equal, NULL, 0);

  printf("scalar_equal\n");
  test_shortint_binary_scalar_op(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, scalar_equal,
      (BinaryScalarCallback)shortint_server_key_smart_scalar_equal, NULL, 0);

  printf("scalar_not_equal\n");
  test_shortint_binary_scalar_op(
      deser_cks, deser_sks, cks_small, sks_small, message_bits, scalar_not_equal,
      (BinaryScalarCallback)shortint_server_key_smart_scalar_not_equal, NULL, 0);

  printf("neg\n");
  test_shortint_unary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, neg,
                         (UnaryCallback)shortint_server_key_smart_neg);
  test_shortint_unary_op(deser_cks, deser_sks, cks_small, sks_small, message_bits, neg,
                         (UnaryCallback)shortint_server_key_unchecked_neg);
  test_shortint_unary_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits, neg,
                                (UnaryAssignCallback)shortint_server_key_smart_neg_assign);
  test_shortint_unary_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits, neg,
                                (UnaryAssignCallback)shortint_server_key_unchecked_neg_assign);

  printf("div\n");
  test_shortint_div(deser_cks, deser_sks, cks_small, sks_small, message_bits);
  test_shortint_div(deser_cks, deser_sks, cks_small, sks_small, message_bits);
  test_shortint_div_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits);
  test_shortint_div_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits);

  printf("scalar_div\n");
  uint8_t forbidden_scalar_div_values[1] = {0};
  test_shortint_binary_scalar_op(deser_cks, deser_sks, cks_small, sks_small, message_bits,
                                 scalar_div,
                                 (BinaryScalarCallback)shortint_server_key_unchecked_scalar_div,
                                 forbidden_scalar_div_values, 1);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits,
                                        scalar_div, shortint_server_key_unchecked_scalar_div_assign,
                                        forbidden_scalar_div_values, 1);
  printf("scalar_mod\n");
  uint8_t forbidden_scalar_mod_values[1] = {0};
  test_shortint_binary_scalar_op(deser_cks, deser_sks, cks_small, sks_small, message_bits,
                                 scalar_mod,
                                 (BinaryScalarCallback)shortint_server_key_unchecked_scalar_mod,
                                 forbidden_scalar_mod_values, 1);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, cks_small, sks_small, message_bits,
                                        scalar_mod, shortint_server_key_unchecked_scalar_mod_assign,
                                        forbidden_scalar_mod_values, 1);

  shortint_destroy_client_key(cks);
  shortint_destroy_client_key(cks_small);
  shortint_destroy_compressed_server_key(csks);
  shortint_destroy_server_key(sks);
  shortint_destroy_server_key(sks_small);
  shortint_destroy_client_key(deser_cks);
  shortint_destroy_compressed_server_key(deser_csks);
  shortint_destroy_server_key(deser_sks);
  destroy_buffer(&cks_ser_buffer);
  destroy_buffer(&csks_ser_buffer);
  destroy_buffer(&sks_ser_buffer);
}

int main(void) {
  test_server_key();
  return EXIT_SUCCESS;
}

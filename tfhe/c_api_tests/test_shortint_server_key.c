#include "tfhe.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

void test_shortint_unary_op(const ShortintClientKey *cks, const ShortintServerKey *sks,
                            const uint32_t message_bits, const uint32_t carry_bits,
                            uint64_t (*c_fun)(uint64_t),
                            int (*api_fun)(const ShortintServerKey *, ShortintCiphertext *,
                                           ShortintCiphertext **)) {

  int message_max = 1 << message_bits;

  for (int val_in = 0; val_in < message_max; ++val_in) {
    ShortintCiphertext *ct_in = NULL;
    ShortintCiphertext *ct_result = NULL;

    uint64_t in = (uint64_t)val_in;

    uint64_t expected = c_fun(in) % message_max;

    int encrypt_left_ok = shortints_client_key_encrypt(cks, in, &ct_in);
    assert(encrypt_left_ok == 0);

    int api_call_ok = api_fun(sks, ct_in, &ct_result);
    assert(api_call_ok == 0);

    uint64_t decrypted_result = -1;

    int decrypt_ok = shortints_client_key_decrypt(cks, ct_result, &decrypted_result);
    assert(decrypt_ok == 0);

    assert(decrypted_result == expected);

    destroy_shortint_ciphertext(ct_in);
    destroy_shortint_ciphertext(ct_result);
  }
}

void test_shortint_unary_op_assign(const ShortintClientKey *cks, const ShortintServerKey *sks,
                                   const uint32_t message_bits, const uint32_t carry_bits,
                                   uint64_t (*c_fun)(uint64_t),
                                   int (*api_fun)(const ShortintServerKey *,
                                                  ShortintCiphertext *)) {

  int message_max = 1 << message_bits;

  for (int in = 0; in < message_max; ++in) {
    ShortintCiphertext *ct_in_and_result = NULL;

    uint64_t in = (uint64_t)in;

    uint64_t expected = c_fun(in) % message_max;

    int encrypt_left_ok = shortints_client_key_encrypt(cks, in, &ct_in_and_result);
    assert(encrypt_left_ok == 0);

    int api_call_ok = api_fun(sks, ct_in_and_result);
    assert(api_call_ok == 0);

    uint64_t decrypted_result = -1;

    int decrypt_ok = shortints_client_key_decrypt(cks, ct_in_and_result, &decrypted_result);
    assert(decrypt_ok == 0);

    assert(decrypted_result == expected);

    destroy_shortint_ciphertext(ct_in_and_result);
  }
}

void test_shortint_binary_op(const ShortintClientKey *cks, const ShortintServerKey *sks,
                             const uint32_t message_bits, const uint32_t carry_bits,
                             uint64_t (*c_fun)(uint64_t, uint64_t),
                             int (*api_fun)(const ShortintServerKey *, ShortintCiphertext *,
                                            ShortintCiphertext *, ShortintCiphertext **)) {

  int message_max = 1 << message_bits;

  for (int val_left = 0; val_left < message_max; ++val_left) {
    for (int val_right = 0; val_right < message_max; ++val_right) {
      ShortintCiphertext *ct_left = NULL;
      ShortintCiphertext *ct_right = NULL;
      ShortintCiphertext *ct_result = NULL;

      uint64_t left = (uint64_t)val_left;
      uint64_t right = (uint64_t)val_right;

      uint64_t expected = c_fun(left, right) % message_max;

      int encrypt_left_ok = shortints_client_key_encrypt(cks, left, &ct_left);
      assert(encrypt_left_ok == 0);

      int encrypt_right_ok = shortints_client_key_encrypt(cks, right, &ct_right);
      assert(encrypt_right_ok == 0);

      int api_call_ok = api_fun(sks, ct_left, ct_right, &ct_result);
      assert(api_call_ok == 0);

      uint64_t decrypted_result = -1;

      int decrypt_ok = shortints_client_key_decrypt(cks, ct_result, &decrypted_result);
      assert(decrypt_ok == 0);

      assert(decrypted_result == expected);

      destroy_shortint_ciphertext(ct_left);
      destroy_shortint_ciphertext(ct_right);
      destroy_shortint_ciphertext(ct_result);
    }
  }
}

void test_shortint_binary_op_assign(const ShortintClientKey *cks, const ShortintServerKey *sks,
                                    const uint32_t message_bits, const uint32_t carry_bits,
                                    uint64_t (*c_fun)(uint64_t, uint64_t),
                                    int (*api_fun)(const ShortintServerKey *, ShortintCiphertext *,
                                                   ShortintCiphertext *)) {

  int message_max = 1 << message_bits;

  for (int val_left = 0; val_left < message_max; ++val_left) {
    for (int val_right = 0; val_right < message_max; ++val_right) {
      ShortintCiphertext *ct_left_and_result = NULL;
      ShortintCiphertext *ct_right = NULL;

      uint64_t left = (uint64_t)val_left;
      uint64_t right = (uint64_t)val_right;

      uint64_t expected = c_fun(left, right) % message_max;

      int encrypt_left_ok = shortints_client_key_encrypt(cks, left, &ct_left_and_result);
      assert(encrypt_left_ok == 0);

      int encrypt_right_ok = shortints_client_key_encrypt(cks, right, &ct_right);
      assert(encrypt_right_ok == 0);

      int api_call_ok = api_fun(sks, ct_left_and_result, ct_right);
      assert(api_call_ok == 0);

      uint64_t decrypted_result = -1;

      int decrypt_ok = shortints_client_key_decrypt(cks, ct_left_and_result, &decrypted_result);
      assert(decrypt_ok == 0);

      assert(decrypted_result == expected);

      destroy_shortint_ciphertext(ct_left_and_result);
      destroy_shortint_ciphertext(ct_right);
    }
  }
}

void test_shortint_binary_scalar_op(
    const ShortintClientKey *cks, const ShortintServerKey *sks, const uint32_t message_bits,
    const uint32_t carry_bits, uint64_t (*c_fun)(uint64_t, uint8_t),
    int (*api_fun)(const ShortintServerKey *, ShortintCiphertext *, uint8_t, ShortintCiphertext **),
    uint8_t forbidden_scalar_values[], size_t forbidden_scalar_values_len) {

  int message_max = 1 << message_bits;

  for (int val_left = 0; val_left < message_max; ++val_left) {
    for (int val_right = 0; val_right < message_max; ++val_right) {
      ShortintCiphertext *ct_left = NULL;
      ShortintCiphertext *ct_result = NULL;

      uint64_t left = (uint64_t)val_left;
      uint8_t scalar_right = (uint8_t)val_right;

      if (forbidden_scalar_values != NULL) {
        bool found_forbiden_value = false;
        for (int idx = 0; idx < forbidden_scalar_values_len; ++idx) {
          if (forbidden_scalar_values[idx] == scalar_right) {
            found_forbiden_value = true;
            break;
          }
        }

        if (found_forbiden_value) {
          continue;
        }
      }

      uint64_t expected = c_fun(left, scalar_right) % message_max;

      int encrypt_left_ok = shortints_client_key_encrypt(cks, left, &ct_left);
      assert(encrypt_left_ok == 0);

      int api_call_ok = api_fun(sks, ct_left, scalar_right, &ct_result);
      assert(api_call_ok == 0);

      uint64_t decrypted_result = -1;

      int decrypt_ok = shortints_client_key_decrypt(cks, ct_result, &decrypted_result);
      assert(decrypt_ok == 0);

      assert(decrypted_result == expected);

      destroy_shortint_ciphertext(ct_left);
      destroy_shortint_ciphertext(ct_result);
    }
  }
}

void test_shortint_binary_scalar_op_assign(
    const ShortintClientKey *cks, const ShortintServerKey *sks, const uint32_t message_bits,
    const uint32_t carry_bits, uint64_t (*c_fun)(uint64_t, uint8_t),
    int (*api_fun)(const ShortintServerKey *, ShortintCiphertext *, uint8_t),
    uint8_t forbidden_scalar_values[], size_t forbidden_scalar_values_len) {

  int message_max = 1 << message_bits;

  for (int val_left = 0; val_left < message_max; ++val_left) {
    for (int val_right = 0; val_right < message_max; ++val_right) {
      ShortintCiphertext *ct_left_and_result = NULL;

      uint64_t left = (uint64_t)val_left;
      uint8_t scalar_right = (uint8_t)val_right;

      if (forbidden_scalar_values != NULL) {
        bool found_forbiden_value = false;
        for (int idx = 0; idx < forbidden_scalar_values_len; ++idx) {
          if (forbidden_scalar_values[idx] == scalar_right) {
            found_forbiden_value = true;
            break;
          }
        }

        if (found_forbiden_value) {
          continue;
        }
      }

      uint64_t expected = c_fun(left, scalar_right) % message_max;

      int encrypt_left_ok = shortints_client_key_encrypt(cks, left, &ct_left_and_result);
      assert(encrypt_left_ok == 0);

      int api_call_ok = api_fun(sks, ct_left_and_result, scalar_right);
      assert(api_call_ok == 0);

      uint64_t decrypted_result = -1;

      int decrypt_ok = shortints_client_key_decrypt(cks, ct_left_and_result, &decrypted_result);
      assert(decrypt_ok == 0);

      assert(decrypted_result == expected);

      destroy_shortint_ciphertext(ct_left_and_result);
    }
  }
}

uint64_t add(uint64_t left, uint64_t right) { return left + right; }
uint64_t sub(uint64_t left, uint64_t right) { return left - right; }
uint64_t mul(uint64_t left, uint64_t right) { return left * right; }
uint64_t neg(uint64_t in) { return -in; }

uint64_t homomorphic_div(uint64_t left, uint64_t right) {
  if (right != 0) {
    return left / right;
  } else {
    // Special value chosen in the shortint implementation in case of a division by 0
    return 0;
  }
}

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

uint64_t left_shift(uint64_t left, uint8_t right) { return left << right; }
uint64_t right_shift(uint64_t left, uint8_t right) { return left >> right; }

void test_server_key(void) {
  ShortintClientKey *cks = NULL;
  ShortintServerKey *sks = NULL;
  Buffer cks_ser_buffer = {.pointer = NULL, .length = 0};
  ShortintClientKey *deser_cks = NULL;
  Buffer sks_ser_buffer = {.pointer = NULL, .length = 0};
  ShortintServerKey *deser_sks = NULL;
  ShortintParameters *params = NULL;

  const uint32_t message_bits = 2;
  const uint32_t carry_bits = 2;

  int get_params_ok = shortints_get_parameters(message_bits, carry_bits, &params);
  assert(get_params_ok == 0);

  int gen_keys_ok = shortints_gen_keys_with_parameters(params, &cks, &sks);
  assert(gen_keys_ok == 0);

  int ser_cks_ok = shortints_serialize_client_key(cks, &cks_ser_buffer);
  assert(ser_cks_ok == 0);

  BufferView deser_view = {.pointer = cks_ser_buffer.pointer, .length = cks_ser_buffer.length};

  int deser_cks_ok = shortints_deserialize_client_key(deser_view, &deser_cks);
  assert(deser_cks_ok == 0);

  int ser_sks_ok = shortints_serialize_server_key(sks, &sks_ser_buffer);
  assert(ser_sks_ok == 0);

  deser_view.pointer = sks_ser_buffer.pointer;
  deser_view.length = sks_ser_buffer.length;

  int deser_sks_ok = shortints_deserialize_server_key(deser_view, &deser_sks);
  assert(deser_sks_ok == 0);

  printf("add\n");
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, add,
                          shortints_server_key_smart_add);
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, add,
                          shortints_server_key_unchecked_add);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, add,
                                 shortints_server_key_smart_add_assign);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, add,
                                 shortints_server_key_unchecked_add_assign);

  printf("sub\n");
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, sub,
                          shortints_server_key_smart_sub);
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, sub,
                          shortints_server_key_unchecked_sub);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, sub,
                                 shortints_server_key_smart_sub_assign);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, sub,
                                 shortints_server_key_unchecked_sub_assign);

  printf("mul\n");
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, mul,
                          shortints_server_key_smart_mul);
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, mul,
                          shortints_server_key_unchecked_mul);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, mul,
                                 shortints_server_key_smart_mul_assign);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, mul,
                                 shortints_server_key_unchecked_mul_assign);

  printf("left_shift\n");
  test_shortint_binary_scalar_op(deser_cks, deser_sks, message_bits, carry_bits, left_shift,
                                 shortints_server_key_smart_scalar_left_shift, NULL, 0);
  test_shortint_binary_scalar_op(deser_cks, deser_sks, message_bits, carry_bits, left_shift,
                                 shortints_server_key_unchecked_scalar_left_shift, NULL, 0);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, message_bits, carry_bits, left_shift,
                                        shortints_server_key_smart_scalar_left_shift_assign, NULL,
                                        0);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, message_bits, carry_bits, left_shift,
                                        shortints_server_key_unchecked_scalar_left_shift_assign,
                                        NULL, 0);

  printf("right_shift\n");
  test_shortint_binary_scalar_op(deser_cks, deser_sks, message_bits, carry_bits, right_shift,
                                 shortints_server_key_smart_scalar_right_shift, NULL, 0);
  test_shortint_binary_scalar_op(deser_cks, deser_sks, message_bits, carry_bits, right_shift,
                                 shortints_server_key_unchecked_scalar_right_shift, NULL, 0);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, message_bits, carry_bits, right_shift,
                                        shortints_server_key_smart_scalar_right_shift_assign, NULL,
                                        0);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, message_bits, carry_bits, right_shift,
                                        shortints_server_key_unchecked_scalar_right_shift_assign,
                                        NULL, 0);

  printf("scalar_add\n");
  test_shortint_binary_scalar_op(deser_cks, deser_sks, message_bits, carry_bits, scalar_add,
                                 shortints_server_key_smart_scalar_add, NULL, 0);
  test_shortint_binary_scalar_op(deser_cks, deser_sks, message_bits, carry_bits, scalar_add,
                                 shortints_server_key_unchecked_scalar_add, NULL, 0);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, message_bits, carry_bits, scalar_add,
                                        shortints_server_key_smart_scalar_add_assign, NULL, 0);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, message_bits, carry_bits, scalar_add,
                                        shortints_server_key_unchecked_scalar_add_assign, NULL, 0);

  printf("scalar_sub\n");
  test_shortint_binary_scalar_op(deser_cks, deser_sks, message_bits, carry_bits, scalar_sub,
                                 shortints_server_key_smart_scalar_sub, NULL, 0);
  test_shortint_binary_scalar_op(deser_cks, deser_sks, message_bits, carry_bits, scalar_sub,
                                 shortints_server_key_unchecked_scalar_sub, NULL, 0);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, message_bits, carry_bits, scalar_sub,
                                        shortints_server_key_smart_scalar_sub_assign, NULL, 0);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, message_bits, carry_bits, scalar_sub,
                                        shortints_server_key_unchecked_scalar_sub_assign, NULL, 0);

  printf("scalar_mul\n");
  test_shortint_binary_scalar_op(deser_cks, deser_sks, message_bits, carry_bits, scalar_mul,
                                 shortints_server_key_smart_scalar_mul, NULL, 0);
  test_shortint_binary_scalar_op(deser_cks, deser_sks, message_bits, carry_bits, scalar_mul,
                                 shortints_server_key_unchecked_scalar_mul, NULL, 0);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, message_bits, carry_bits, scalar_mul,
                                        shortints_server_key_smart_scalar_mul_assign, NULL, 0);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, message_bits, carry_bits, scalar_mul,
                                        shortints_server_key_unchecked_scalar_mul_assign, NULL, 0);

  printf("bitand\n");
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, bitand,
                          shortints_server_key_smart_bitand);
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, bitand,
                          shortints_server_key_unchecked_bitand);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, bitand,
                                 shortints_server_key_smart_bitand_assign);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, bitand,
                                 shortints_server_key_unchecked_bitand_assign);

  printf("bitxor\n");
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, bitxor,
                          shortints_server_key_smart_bitxor);
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, bitxor,
                          shortints_server_key_unchecked_bitxor);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, bitxor,
                                 shortints_server_key_smart_bitxor_assign);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, bitxor,
                                 shortints_server_key_unchecked_bitxor_assign);

  printf("bitor\n");
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, bitor,
                          shortints_server_key_smart_bitor);
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, bitor,
                          shortints_server_key_unchecked_bitor);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, bitor,
                                 shortints_server_key_smart_bitor_assign);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, bitor,
                                 shortints_server_key_unchecked_bitor_assign);

  printf("greater\n");
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, greater,
                          shortints_server_key_smart_greater);
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, greater,
                          shortints_server_key_unchecked_greater);

  printf("greater_or_equal\n");
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, greater_or_equal,
                          shortints_server_key_smart_greater_or_equal);
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, greater_or_equal,
                          shortints_server_key_unchecked_greater_or_equal);

  printf("less\n");
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, less,
                          shortints_server_key_smart_less);
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, less,
                          shortints_server_key_unchecked_less);

  printf("less_or_equal\n");
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, less_or_equal,
                          shortints_server_key_smart_less_or_equal);
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, less_or_equal,
                          shortints_server_key_unchecked_less_or_equal);

  printf("equal\n");
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, equal,
                          shortints_server_key_smart_equal);
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, equal,
                          shortints_server_key_unchecked_equal);

  printf("not_equal\n");
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, not_equal,
                          shortints_server_key_smart_not_equal);
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, not_equal,
                          shortints_server_key_unchecked_not_equal);

  printf("scalar_greater\n");
  test_shortint_binary_scalar_op(deser_cks, deser_sks, message_bits, carry_bits, scalar_greater,
                                 shortints_server_key_smart_scalar_greater, NULL, 0);

  printf("scalar_greater_or_equal\n");
  test_shortint_binary_scalar_op(deser_cks, deser_sks, message_bits, carry_bits,
                                 scalar_greater_or_equal,
                                 shortints_server_key_smart_scalar_greater_or_equal, NULL, 0);

  printf("scalar_less\n");
  test_shortint_binary_scalar_op(deser_cks, deser_sks, message_bits, carry_bits, scalar_less,
                                 shortints_server_key_smart_scalar_less, NULL, 0);

  printf("scalar_less_or_equal\n");
  test_shortint_binary_scalar_op(deser_cks, deser_sks, message_bits, carry_bits,
                                 scalar_less_or_equal,
                                 shortints_server_key_smart_scalar_less_or_equal, NULL, 0);

  printf("scalar_equal\n");
  test_shortint_binary_scalar_op(deser_cks, deser_sks, message_bits, carry_bits, scalar_equal,
                                 shortints_server_key_smart_scalar_equal, NULL, 0);

  printf("scalar_not_equal\n");
  test_shortint_binary_scalar_op(deser_cks, deser_sks, message_bits, carry_bits, scalar_not_equal,
                                 shortints_server_key_smart_scalar_not_equal, NULL, 0);

  printf("neg\n");
  test_shortint_unary_op(deser_cks, deser_sks, message_bits, carry_bits, neg,
                         shortints_server_key_smart_neg);
  test_shortint_unary_op(deser_cks, deser_sks, message_bits, carry_bits, neg,
                         shortints_server_key_unchecked_neg);
  test_shortint_unary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, neg,
                                shortints_server_key_smart_neg_assign);
  test_shortint_unary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, neg,
                                shortints_server_key_unchecked_neg_assign);

  printf("div\n");
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, homomorphic_div,
                          shortints_server_key_smart_div);
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, homomorphic_div,
                          shortints_server_key_unchecked_div);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, homomorphic_div,
                                 shortints_server_key_smart_div_assign);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, homomorphic_div,
                                 shortints_server_key_unchecked_div_assign);

  printf("scalar_div\n");
  uint8_t forbiden_scalar_div_values[1] = {0};
  test_shortint_binary_scalar_op(deser_cks, deser_sks, message_bits, carry_bits, scalar_div,
                                 shortints_server_key_unchecked_scalar_div,
                                 forbiden_scalar_div_values, 1);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, message_bits, carry_bits, scalar_div,
                                        shortints_server_key_unchecked_scalar_div_assign,
                                        forbiden_scalar_div_values, 1);

  destroy_shortint_client_key(cks);
  destroy_shortint_server_key(sks);
  destroy_shortint_client_key(deser_cks);
  destroy_shortint_server_key(deser_sks);
  destroy_shortint_parameters(params);
  destroy_buffer(&cks_ser_buffer);
  destroy_buffer(&sks_ser_buffer);
}

int main(void) {
  test_server_key();
  return EXIT_SUCCESS;
}

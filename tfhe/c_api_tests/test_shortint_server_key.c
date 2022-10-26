#include "tfhe.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <tgmath.h>

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

void test_shortint_binary_scalar_op(const ShortintClientKey *cks, const ShortintServerKey *sks,
                                    const uint32_t message_bits, const uint32_t carry_bits,
                                    uint64_t (*c_fun)(uint64_t, uint8_t),
                                    int (*api_fun)(const ShortintServerKey *, ShortintCiphertext *,
                                                   uint8_t, ShortintCiphertext **)) {

  int message_max = 1 << message_bits;

  for (int val_left = 0; val_left < message_max; ++val_left) {
    for (int val_right = 0; val_right < 256; ++val_right) {
      ShortintCiphertext *ct_left = NULL;
      ShortintCiphertext *ct_result = NULL;

      uint64_t left = (uint64_t)val_left;
      uint8_t scalar_right = (uint8_t)val_right;

      uint64_t expected = c_fun(left, scalar_right) % message_max;

      int encrypt_left_ok = shortints_client_key_encrypt(cks, left, &ct_left);
      assert(encrypt_left_ok == 0);

      int api_call_ok = api_fun(sks, ct_left, scalar_right, &ct_result);
      assert(api_call_ok == 0);

      uint64_t decrypted_result = -1;

      int decrypt_ok = shortints_client_key_decrypt(cks, ct_result, &decrypted_result);
      assert(decrypt_ok == 0);

      printf("left: %ld, right: %d\n", left, scalar_right);
      printf("decrypted_result: %ld, expected %ld\n", decrypted_result, expected);
      assert(decrypted_result == expected);

      destroy_shortint_ciphertext(ct_left);
      destroy_shortint_ciphertext(ct_result);
    }
  }
}

void test_shortint_binary_scalar_op_assign(
    const ShortintClientKey *cks, const ShortintServerKey *sks, const uint32_t message_bits,
    const uint32_t carry_bits, uint64_t (*c_fun)(uint64_t, uint8_t),
    int (*api_fun)(const ShortintServerKey *, ShortintCiphertext *, uint8_t)) {

  int message_max = 1 << message_bits;

  for (int val_left = 0; val_left < message_max; ++val_left) {
    for (int val_right = 0; val_right < 256; ++val_right) {
      ShortintCiphertext *ct_left_and_result = NULL;

      uint64_t left = (uint64_t)val_left;
      uint8_t scalar_right = (uint8_t)val_right;

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

uint64_t left_shift(uint64_t left, uint8_t right) { return left << right; }

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

  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, add,
                          shortints_server_key_smart_add);
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, add,
                          shortints_server_key_unchecked_add);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, add,
                                 shortints_server_key_smart_add_assign);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, add,
                                 shortints_server_key_unchecked_add_assign);

  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, sub,
                          shortints_server_key_smart_sub);
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, sub,
                          shortints_server_key_unchecked_sub);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, sub,
                                 shortints_server_key_smart_sub_assign);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, sub,
                                 shortints_server_key_unchecked_sub_assign);

  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, mul,
                          shortints_server_key_smart_mul);
  test_shortint_binary_op(deser_cks, deser_sks, message_bits, carry_bits, mul,
                          shortints_server_key_unchecked_mul);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, mul,
                                 shortints_server_key_smart_mul_assign);
  test_shortint_binary_op_assign(deser_cks, deser_sks, message_bits, carry_bits, mul,
                                 shortints_server_key_unchecked_mul_assign);

  test_shortint_binary_scalar_op(deser_cks, deser_sks, message_bits, carry_bits, left_shift,
                                 shortints_server_key_smart_scalar_left_shift);
  test_shortint_binary_scalar_op(deser_cks, deser_sks, message_bits, carry_bits, left_shift,
                                 shortints_server_key_unchecked_scalar_left_shift);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, message_bits, carry_bits, left_shift,
                                        shortints_server_key_smart_scalar_left_shift_assign);
  test_shortint_binary_scalar_op_assign(deser_cks, deser_sks, message_bits, carry_bits, left_shift,
                                        shortints_server_key_unchecked_scalar_left_shift_assign);

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

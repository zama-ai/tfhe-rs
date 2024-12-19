#include "tfhe.h"

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#define assert_m(condition, format, ...)                                                           \
  do {                                                                                             \
    if (!(condition)) {                                                                            \
      fprintf(stderr, "%s::%d::%s: condition `%s` failed.\n" format "\n", __FILE__, __LINE__,      \
              __func__, #condition, ##__VA_ARGS__);                                                \
      abort();                                                                                     \
    }                                                                                              \
  } while (0)

int uint8_client_key(const ClientKey *client_key) {
  int ok;
  FheUint8 *lhs = NULL;
  FheUint8 *rhs = NULL;
  FheUint8 *result = NULL;

  uint8_t lhs_clear = 123;
  uint8_t rhs_clear = 14;

  ok = fhe_uint8_try_encrypt_with_client_key_u8(lhs_clear, client_key, &lhs);
  assert(ok == 0);

  ok = fhe_uint8_try_encrypt_with_client_key_u8(rhs_clear, client_key, &rhs);
  assert(ok == 0);

  uint8_t clear;

  // Check addition
  {
    ok = fhe_uint8_add(lhs, rhs, &result);
    assert(ok == 0);

    ok = fhe_uint8_decrypt(result, client_key, &clear);
    assert(ok == 0);

    assert(clear == (lhs_clear + rhs_clear));
  }

  // Check sum
  {
    FheUint8 *sum_result;
    const FheUint8 *data[2] = {lhs, rhs};
    ok = fhe_uint8_sum(data, 2, &sum_result);
    assert(ok == 0);

    clear = 0;
    ok = fhe_uint8_decrypt(result, client_key, &clear);
    assert(ok == 0);

    assert(clear == (lhs_clear + rhs_clear));
    fhe_uint8_destroy(sum_result);
  }

  fhe_uint8_destroy(lhs);
  fhe_uint8_destroy(rhs);
  fhe_uint8_destroy(result);
  return ok;
}

void test_uint8_overflowing_add(const ClientKey *client_key) {
  int ok;
  FheUint8 *lhs = NULL;
  FheUint8 *rhs = NULL;
  FheUint8 *result = NULL;
  FheBool *overflowed = NULL;

  uint8_t lhs_clear = UINT8_MAX;
  uint8_t rhs_clear = 1;

  ok = fhe_uint8_try_encrypt_with_client_key_u8(lhs_clear, client_key, &lhs);
  assert(ok == 0);

  ok = fhe_uint8_try_encrypt_with_client_key_u8(rhs_clear, client_key, &rhs);
  assert(ok == 0);

  uint8_t clear_result;
  bool clear_overflowed;

  // Check
  {
    ok = fhe_uint8_overflowing_add(lhs, rhs, &result, &overflowed);
    assert(ok == 0);

    ok = fhe_uint8_decrypt(result, client_key, &clear_result);
    assert(ok == 0);

    ok = fhe_bool_decrypt(overflowed, client_key, &clear_overflowed);
    assert(ok == 0);

    uint8_t expected_result = lhs_clear + rhs_clear;
    assert_m(clear_result == expected_result,
             "Invalid result for overflowing_add(%" PRIu8 ", %" PRIu8 "), "
             "expected %" PRIu8 " got %" PRIu8,
             lhs_clear, rhs_clear, expected_result, clear_result);
    assert(clear_overflowed == true);
  }

  fhe_uint8_destroy(lhs);
  fhe_uint8_destroy(rhs);
  fhe_uint8_destroy(result);
  fhe_bool_destroy(overflowed);
}

void test_uint8_overflowing_sub(const ClientKey *client_key) {
  int ok;
  FheUint8 *lhs = NULL;
  FheUint8 *rhs = NULL;
  FheUint8 *result = NULL;
  FheBool *overflowed = NULL;

  uint8_t lhs_clear = 0;
  uint8_t rhs_clear = 1;

  ok = fhe_uint8_try_encrypt_with_client_key_u8(lhs_clear, client_key, &lhs);
  assert(ok == 0);

  ok = fhe_uint8_try_encrypt_with_client_key_u8(rhs_clear, client_key, &rhs);
  assert(ok == 0);

  uint8_t clear_result;
  bool clear_overflowed;

  // Check
  {
    ok = fhe_uint8_overflowing_sub(lhs, rhs, &result, &overflowed);
    assert(ok == 0);

    ok = fhe_uint8_decrypt(result, client_key, &clear_result);
    assert(ok == 0);

    ok = fhe_bool_decrypt(overflowed, client_key, &clear_overflowed);
    assert(ok == 0);

    uint8_t expected_result = lhs_clear - rhs_clear;
    assert_m(clear_result == expected_result,
             "Invalid result for overflowing_sub(%" PRIu8 ", %" PRIu8 "), "
             "expected %" PRIu8 " got %" PRIu8,
             lhs_clear, rhs_clear, expected_result, clear_result);
    assert(clear_overflowed == true);
  }

  fhe_uint8_destroy(lhs);
  fhe_uint8_destroy(rhs);
  fhe_uint8_destroy(result);
  fhe_bool_destroy(overflowed);
}

void test_uint8_overflowing_mul(const ClientKey *client_key) {
  int ok;
  FheUint8 *lhs = NULL;
  FheUint8 *rhs = NULL;
  FheUint8 *result = NULL;
  FheBool *overflowed = NULL;

  uint8_t lhs_clear = 123;
  uint8_t rhs_clear = 3;

  ok = fhe_uint8_try_encrypt_with_client_key_u8(lhs_clear, client_key, &lhs);
  assert(ok == 0);

  ok = fhe_uint8_try_encrypt_with_client_key_u8(rhs_clear, client_key, &rhs);
  assert(ok == 0);

  uint8_t clear_result;
  bool clear_overflowed;

  // Check
  {
    ok = fhe_uint8_overflowing_mul(lhs, rhs, &result, &overflowed);
    assert(ok == 0);

    ok = fhe_uint8_decrypt(result, client_key, &clear_result);
    assert(ok == 0);

    ok = fhe_bool_decrypt(overflowed, client_key, &clear_overflowed);
    assert(ok == 0);

    uint8_t expected_result = lhs_clear * rhs_clear;
    assert_m(clear_result == expected_result,
             "Invalid result for overflowing_mul(%" PRIu8 ", %" PRIu8 "), "
             "expected %" PRIu8 " got %" PRIu8,
             lhs_clear, rhs_clear, expected_result, clear_result);
    assert(clear_overflowed == true);
  }

  fhe_uint8_destroy(lhs);
  fhe_uint8_destroy(rhs);
  fhe_uint8_destroy(result);
  fhe_bool_destroy(overflowed);
}

void test_int8_overflowing_add(const ClientKey *client_key) {
  int ok;
  FheInt8 *lhs = NULL;
  FheInt8 *rhs = NULL;
  FheInt8 *result = NULL;
  FheBool *overflowed = NULL;

  int8_t lhs_clear = INT8_MAX;
  int8_t rhs_clear = 1;
  assert((int)INT8_MAX == 127);
  assert((int)INT8_MIN == -128); // C < C23 is not guaranteed to use two's complement

  ok = fhe_int8_try_encrypt_with_client_key_i8(lhs_clear, client_key, &lhs);
  assert(ok == 0);

  ok = fhe_int8_try_encrypt_with_client_key_i8(rhs_clear, client_key, &rhs);
  assert(ok == 0);

  int8_t clear_result;
  bool clear_overflowed;

  // Check
  {
    ok = fhe_int8_overflowing_add(lhs, rhs, &result, &overflowed);
    assert(ok == 0);

    ok = fhe_int8_decrypt(result, client_key, &clear_result);
    assert(ok == 0);

    ok = fhe_bool_decrypt(overflowed, client_key, &clear_overflowed);
    assert(ok == 0);

    // In C, signed overflow is actually undefined behaviour (until C23)
    // so we can't do the addition here, and have to hardcode the result
    int8_t expected_result = INT8_MIN;
    assert_m(clear_result == expected_result,
             "Invalid result for overflowing_add(%" PRIi8 ", %" PRIi8 "), "
             "expected %" PRIi8 " got %" PRIi8,
             lhs_clear, rhs_clear, expected_result, clear_result);
    assert(clear_overflowed == true);
  }

  fhe_int8_destroy(lhs);
  fhe_int8_destroy(rhs);
  fhe_int8_destroy(result);
  fhe_bool_destroy(overflowed);
}

void test_int8_overflowing_sub(const ClientKey *client_key) {
  int ok;
  FheInt8 *lhs = NULL;
  FheInt8 *rhs = NULL;
  FheInt8 *result = NULL;
  FheBool *overflowed = NULL;

  int8_t lhs_clear = INT8_MIN;
  int8_t rhs_clear = 1;
  assert((int)INT8_MAX == 127);
  assert((int)INT8_MIN == -128); // C < C23 is not guaranteed to use two's complement

  ok = fhe_int8_try_encrypt_with_client_key_i8(lhs_clear, client_key, &lhs);
  assert(ok == 0);

  ok = fhe_int8_try_encrypt_with_client_key_i8(rhs_clear, client_key, &rhs);
  assert(ok == 0);

  int8_t clear_result;
  bool clear_overflowed;

  // Check
  {
    ok = fhe_int8_overflowing_sub(lhs, rhs, &result, &overflowed);
    assert(ok == 0);

    ok = fhe_int8_decrypt(result, client_key, &clear_result);
    assert(ok == 0);

    ok = fhe_bool_decrypt(overflowed, client_key, &clear_overflowed);
    assert(ok == 0);

    // In C, signed overflow is actually undefined behaviour (until C23)
    // so we can't do the addition here, and have to hardcode the result
    int8_t expected_result = 127;
    assert_m(clear_result == expected_result,
             "Invalid result for overflowing_sub(%" PRIi8 ", %" PRIi8 "), "
             "expected %" PRIi8 " got %" PRIi8,
             lhs_clear, rhs_clear, expected_result, clear_result);
    assert(clear_overflowed == true);
  }

  fhe_int8_destroy(lhs);
  fhe_int8_destroy(rhs);
  fhe_int8_destroy(result);
  fhe_bool_destroy(overflowed);
}

void test_int8_overflowing_mul(const ClientKey *client_key) {
  int ok;
  FheInt8 *lhs = NULL;
  FheInt8 *rhs = NULL;
  FheInt8 *result = NULL;
  FheBool *overflowed = NULL;

  int8_t lhs_clear = 123;
  int8_t rhs_clear = -17;
  assert((int)INT8_MAX == 127);
  assert((int)INT8_MIN == -128); // C < C23 is not guaranteed to use two's complement

  ok = fhe_int8_try_encrypt_with_client_key_i8(lhs_clear, client_key, &lhs);
  assert(ok == 0);

  ok = fhe_int8_try_encrypt_with_client_key_i8(rhs_clear, client_key, &rhs);
  assert(ok == 0);

  int8_t clear_result;
  bool clear_overflowed;

  // Check
  {
    ok = fhe_int8_overflowing_mul(lhs, rhs, &result, &overflowed);
    assert(ok == 0);

    ok = fhe_int8_decrypt(result, client_key, &clear_result);
    assert(ok == 0);

    ok = fhe_bool_decrypt(overflowed, client_key, &clear_overflowed);
    assert(ok == 0);

    // In C, signed overflow is actually undefined behaviour (until C23)
    // so we can't do the addition here, and have to hardcode the result
    int8_t expected_result = -43;
    assert_m(clear_result == expected_result,
             "Invalid result for overflowing_mul(%" PRIi8 ", %" PRIi8 "), "
             "expected %" PRIi8 " got %" PRIi8,
             lhs_clear, rhs_clear, expected_result, clear_result);
    assert(clear_overflowed == true);
  }

  fhe_int8_destroy(lhs);
  fhe_int8_destroy(rhs);
  fhe_int8_destroy(result);
  fhe_bool_destroy(overflowed);
}

int uint8_public_key(const ClientKey *client_key, const PublicKey *public_key) {
  int ok;
  FheUint8 *lhs = NULL;
  FheUint8 *rhs = NULL;
  FheUint8 *result = NULL;

  uint8_t lhs_clear = 123;
  uint8_t rhs_clear = 14;

  ok = fhe_uint8_try_encrypt_with_public_key_u8(lhs_clear, public_key, &lhs);
  assert(ok == 0);

  ok = fhe_uint8_try_encrypt_with_public_key_u8(rhs_clear, public_key, &rhs);
  assert(ok == 0);

  ok = fhe_uint8_sub(lhs, rhs, &result);
  assert(ok == 0);

  uint8_t clear;
  ok = fhe_uint8_decrypt(result, client_key, &clear);
  assert(ok == 0);

  assert(clear == (lhs_clear - rhs_clear));

  fhe_uint8_destroy(lhs);
  fhe_uint8_destroy(rhs);
  fhe_uint8_destroy(result);
  return ok;
}

int uint8_safe_serialization(const ClientKey *client_key, const ServerKey *server_key) {
  int ok;
  FheUint8 *lhs = NULL;
  FheUint8 *deserialized_lhs = NULL;
  DynamicBuffer value_buffer = {.pointer = NULL, .length = 0, .destructor = NULL};
  DynamicBuffer cks_buffer = {.pointer = NULL, .length = 0, .destructor = NULL};
  DynamicBufferView deser_view = {.pointer = NULL, .length = 0};
  ClientKey *deserialized_client_key = NULL;

  const uint64_t max_serialization_size = UINT64_C(1) << UINT64_C(20);

  uint8_t lhs_clear = 123;

  ok = client_key_serialize(client_key, &cks_buffer);
  assert(ok == 0);

  deser_view.pointer = cks_buffer.pointer;
  deser_view.length = cks_buffer.length;
  ok = client_key_deserialize(deser_view, &deserialized_client_key);
  assert(ok == 0);

  ok = fhe_uint8_try_encrypt_with_client_key_u8(lhs_clear, client_key, &lhs);
  assert(ok == 0);

  ok = fhe_uint8_safe_serialize(lhs, &value_buffer, max_serialization_size);
  assert(ok == 0);

  deser_view.pointer = value_buffer.pointer;
  deser_view.length = value_buffer.length;
  ok = fhe_uint8_safe_deserialize_conformant(deser_view, max_serialization_size, server_key,
                                             &deserialized_lhs);
  assert(ok == 0);

  uint8_t clear;
  ok = fhe_uint8_decrypt(deserialized_lhs, deserialized_client_key, &clear);
  assert(ok == 0);

  assert(clear == lhs_clear);

  if (value_buffer.pointer != NULL) {
    destroy_dynamic_buffer(&value_buffer);
  }
  fhe_uint8_destroy(lhs);
  fhe_uint8_destroy(deserialized_lhs);
  return ok;
}

int uint8_serialization(const ClientKey *client_key) {
  int ok;
  FheUint8 *lhs = NULL;
  FheUint8 *deserialized_lhs = NULL;
  DynamicBuffer value_buffer = {.pointer = NULL, .length = 0, .destructor = NULL};
  DynamicBuffer cks_buffer = {.pointer = NULL, .length = 0, .destructor = NULL};
  DynamicBufferView deser_view = {.pointer = NULL, .length = 0};
  ClientKey *deserialized_client_key = NULL;

  uint8_t lhs_clear = 123;

  ok = client_key_serialize(client_key, &cks_buffer);
  assert(ok == 0);

  deser_view.pointer = cks_buffer.pointer;
  deser_view.length = cks_buffer.length;
  ok = client_key_deserialize(deser_view, &deserialized_client_key);
  assert(ok == 0);

  ok = fhe_uint8_try_encrypt_with_client_key_u8(lhs_clear, deserialized_client_key, &lhs);
  assert(ok == 0);

  ok = fhe_uint8_serialize(lhs, &value_buffer);
  assert(ok == 0);

  deser_view.pointer = value_buffer.pointer;
  deser_view.length = value_buffer.length;
  ok = fhe_uint8_deserialize(deser_view, &deserialized_lhs);
  assert(ok == 0);

  uint8_t clear;
  ok = fhe_uint8_decrypt(deserialized_lhs, deserialized_client_key, &clear);
  assert(ok == 0);

  assert(clear == lhs_clear);

  if (value_buffer.pointer != NULL) {
    destroy_dynamic_buffer(&value_buffer);
  }
  fhe_uint8_destroy(lhs);
  fhe_uint8_destroy(deserialized_lhs);
  return ok;
}

int uint8_compressed(const ClientKey *client_key) {
  int ok;
  FheUint8 *lhs = NULL;
  FheUint8 *result = NULL;
  CompressedFheUint8 *clhs = NULL;

  uint8_t lhs_clear = 123;

  ok = compressed_fhe_uint8_try_encrypt_with_client_key_u8(lhs_clear, client_key, &clhs);
  assert(ok == 0);

  ok = compressed_fhe_uint8_decompress(clhs, &lhs);
  assert(ok == 0);

  uint8_t clear;
  ok = fhe_uint8_decrypt(lhs, client_key, &clear);
  assert(ok == 0);

  assert(clear == lhs_clear);

  fhe_uint8_destroy(lhs);
  compressed_fhe_uint8_destroy(clhs);
  return ok;
}

int uint8_compressed_after_encryption(const ClientKey *client_key) {
  int ok;
  FheUint8 *lhs = NULL;
  FheUint8 *result = NULL;
  CompressedFheUint8 *clhs = NULL;

  uint8_t lhs_clear = 123;

  ok = fhe_uint8_try_encrypt_with_client_key_u8(lhs_clear, client_key, &lhs);
  assert(ok == 0);

  ok = fhe_uint8_compress(lhs, &clhs);
  assert(ok == 0);

  ok = compressed_fhe_uint8_decompress(clhs, &lhs);
  assert(ok == 0);

  uint8_t clear;
  ok = fhe_uint8_decrypt(lhs, client_key, &clear);
  assert(ok == 0);

  assert(clear == lhs_clear);

  fhe_uint8_destroy(lhs);
  compressed_fhe_uint8_destroy(clhs);
  fhe_uint8_destroy(result);
  return ok;
}

void test_try_decrypt_trivial(const ClientKey *client_key) {
  const uint16_t clear = UINT16_MAX - 2;

  FheUint16 *trivial = NULL;
  int status = fhe_uint16_try_encrypt_trivial_u16(clear, &trivial);
  assert(status == 0);

  FheUint16 *non_trivial = NULL;
  status = fhe_uint16_try_encrypt_with_client_key_u16(clear, client_key, &non_trivial);
  assert(status == 0);

  /* Example of decrypting a trivial */
  uint16_t decrypted;
  status = fhe_uint16_try_decrypt_trivial(trivial, &decrypted);
  assert(status == 0);
  assert(decrypted == clear);

  /* Example of trying to trivial decrypt a ciphertext that is not trivial */
  status = fhe_uint16_try_decrypt_trivial(non_trivial, &decrypted);
  assert(status == 1); // Returns that its an error

  fhe_uint16_destroy(trivial);
  fhe_uint16_destroy(non_trivial);
}

void test_oprf(const ClientKey *client_key) {
  {
    FheUint8 *ct = NULL;

    int status = generate_oblivious_pseudo_random_fhe_uint8(&ct, 0, 0);
    assert(status == 0);

    uint8_t decrypted;
    status = fhe_uint8_decrypt(ct, client_key, &decrypted);
    // nothing to assert here, as decrypted can be any uint8_t value

    fhe_uint8_destroy(ct);

    status = generate_oblivious_pseudo_random_bounded_fhe_uint8(&ct, 0, 0, 2);
    assert(status == 0);

    status = fhe_uint8_decrypt(ct, client_key, &decrypted);
    assert(status == 0);

    assert(decrypted < 4);

    fhe_uint8_destroy(ct);
  }

  {
    FheInt8 *ct = NULL;

    int status = generate_oblivious_pseudo_random_fhe_int8(&ct, 0, 0);
    assert(status == 0);

    int8_t decrypted;
    status = fhe_int8_decrypt(ct, client_key, &decrypted);
    assert(status == 0);
    // nothing to assert here, as decrypted can be any int8_t value

    fhe_int8_destroy(ct);

    status = generate_oblivious_pseudo_random_bounded_fhe_int8(&ct, 0, 0, 2);
    assert(status == 0);

    status = fhe_int8_decrypt(ct, client_key, &decrypted);
    assert(status == 0);

    assert(decrypted < 4);
    assert(decrypted >= 0);
  }
}

int main(void) {
  int ok = 0;
  {
    ConfigBuilder *builder;
    Config *config;

    ok = config_builder_default(&builder);
    assert(ok == 0);
    ok = config_builder_build(builder, &config);
    assert(ok == 0);

    ClientKey *client_key = NULL;
    ServerKey *server_key = NULL;
    PublicKey *public_key = NULL;

    ok = generate_keys(config, &client_key, &server_key);
    assert(ok == 0);
    ok = public_key_new(client_key, &public_key);
    assert(ok == 0);
    ok = uint8_serialization(client_key);
    assert(ok == 0);
    ok = uint8_safe_serialization(client_key, server_key);
    assert(ok == 0);
    ok = uint8_compressed(client_key);
    assert(ok == 0);

    ok = set_server_key(server_key);
    assert(ok == 0);

    ok = uint8_compressed_after_encryption(client_key);
    assert(ok == 0);

    ok = uint8_client_key(client_key);
    assert(ok == 0);
    ok = uint8_public_key(client_key, public_key);
    assert(ok == 0);

    test_uint8_overflowing_add(client_key);
    test_uint8_overflowing_sub(client_key);
    test_uint8_overflowing_mul(client_key);
    test_int8_overflowing_add(client_key);
    test_int8_overflowing_sub(client_key);
    test_int8_overflowing_mul(client_key);
    test_try_decrypt_trivial(client_key);
    test_oprf(client_key);

    client_key_destroy(client_key);
    public_key_destroy(public_key);
    server_key_destroy(server_key);
  }

  {
    ConfigBuilder *builder;
    Config *config;

    // Set config builder in default state
    ok = config_builder_default(&builder);
    assert(ok == 0);
    // Then use small parameters, those are gaussians as we don't have small TUniform params
    ok = config_builder_use_custom_parameters(
        &builder, SHORTINT_V0_11_PARAM_MESSAGE_2_CARRY_2_PBS_KS_GAUSSIAN_2M64);
    ok = config_builder_build(builder, &config);
    assert(ok == 0);

    ClientKey *client_key = NULL;
    ServerKey *server_key = NULL;
    PublicKey *public_key = NULL;

    ok = generate_keys(config, &client_key, &server_key);
    assert(ok == 0);
    ok = public_key_new(client_key, &public_key);
    assert(ok == 0);

    ok = set_server_key(server_key);
    assert(ok == 0);

    ok = uint8_client_key(client_key);
    assert(ok == 0);

    ok = uint8_public_key(client_key, public_key);
    assert(ok == 0);

    test_uint8_overflowing_add(client_key);
    test_uint8_overflowing_sub(client_key);
    test_uint8_overflowing_mul(client_key);
    test_int8_overflowing_add(client_key);
    test_int8_overflowing_sub(client_key);
    test_int8_overflowing_mul(client_key);
    test_try_decrypt_trivial(client_key);

    client_key_destroy(client_key);
    public_key_destroy(public_key);
    server_key_destroy(server_key);
  }

  return ok;
}

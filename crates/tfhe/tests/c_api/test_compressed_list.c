#include "tfhe.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

int main(void) {
  int ok = 0;

  // First, we create a ClientKey and a CompactPublicKey
  ClientKey *client_key = NULL;
  ServerKey *server_key = NULL;

  {
    ConfigBuilder *builder;
    Config *config;

    ok = config_builder_default(&builder);
    assert(ok == 0);

    ok = config_builder_use_custom_parameters(
        &builder, SHORTINT_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
    assert(ok == 0);

    ok = config_builder_enable_compression(
        &builder, &SHORTINT_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
    assert(ok == 0);

    ok = config_builder_build(builder, &config);
    assert(ok == 0);

    ok = generate_keys(config, &client_key, &server_key);
    assert(ok == 0);

    ok = set_server_key(server_key);
    assert(ok == 0);
  }

  // Then, we create the compact list
  CompressedCiphertextList *list = NULL;
  {
    CompressedCiphertextListBuilder *builder;
    ok = compressed_ciphertext_list_builder_new(&builder);
    assert(ok == 0);

    FheUint32 *a = NULL;
    FheInt64 *b = NULL;
    FheBool *c = NULL;
    FheUint2 *d = NULL;

    // Encrypt
    {
      ok = fhe_uint32_try_encrypt_with_client_key_u32(38382, client_key, &a);
      assert(ok == 0);

      ok = fhe_int64_try_encrypt_with_client_key_i64(-1, client_key, &b);
      assert(ok == 0);

      ok = fhe_bool_try_encrypt_with_client_key_bool(true, client_key, &c);
      assert(ok == 0);

      ok = fhe_uint2_try_encrypt_with_client_key_u8(3, client_key, &d);
      assert(ok == 0);
    }

    // Push some values
    ok = compressed_ciphertext_list_builder_push_u32(builder, a);
    assert(ok == 0);

    ok = compressed_ciphertext_list_builder_push_i64(builder, b);
    assert(ok == 0);

    ok = compressed_ciphertext_list_builder_push_bool(builder, c);
    assert(ok == 0);

    ok = compressed_ciphertext_list_builder_push_u2(builder, d);
    assert(ok == 0);

    ok = compressed_ciphertext_list_builder_build(builder, &list);
    assert(ok == 0);

    // Don't forget to destroy the builder
    compressed_ciphertext_list_builder_destroy(builder);
  }

  // Now we can expand values
  FheUint32 *a = NULL;
  FheInt64 *b = NULL;
  FheBool *c = NULL;
  FheUint2 *d = NULL;
  {
    FheTypes type = Type_FheBool;

    size_t len = 0;
    ok = compressed_ciphertext_list_len(list, &len);
    assert(ok == 0 && len == 4);

    // First, an example of getting the type in a slot
    ok = compressed_ciphertext_list_get_kind_of(list, 0, &type);
    assert(ok == 0 && type == Type_FheUint32);

    ok = compressed_ciphertext_list_get_kind_of(list, 1, &type);
    assert(ok == 0 && type == Type_FheInt64);

    ok = compressed_ciphertext_list_get_kind_of(list, 2, &type);
    assert(ok == 0 && type == Type_FheBool);

    ok = compressed_ciphertext_list_get_kind_of(list, 3, &type);
    assert(ok == 0 && type == Type_FheUint2);

    // Then how to get the values
    ok = compressed_ciphertext_list_get_fhe_uint32(list, 0, &a);
    assert(ok == 0);

    ok = compressed_ciphertext_list_get_fhe_int64(list, 1, &b);
    assert(ok == 0);

    ok = compressed_ciphertext_list_get_fhe_bool(list, 2, &c);
    assert(ok == 0);

    ok = compressed_ciphertext_list_get_fhe_uint2(list, 3, &d);
    assert(ok == 0);
  }

  uint32_t clear_a = 0;
  ok = fhe_uint32_decrypt(a, client_key, &clear_a);
  assert(ok == 0);
  assert(clear_a == 38382);

  int64_t clear_b = 0;
  ok = fhe_int64_decrypt(b, client_key, &clear_b);
  assert(ok == 0);
  assert(clear_b == -1);

  bool clear_c = false;
  ok = fhe_bool_decrypt(c, client_key, &clear_c);
  assert(ok == 0);
  assert(clear_c == true);

  uint8_t clear_d = 0;
  ok = fhe_uint2_decrypt(d, client_key, &clear_d);
  assert(ok == 0);
  assert(clear_d == 3);

  fhe_uint32_destroy(a);
  fhe_int64_destroy(b);
  fhe_bool_destroy(c);
  fhe_uint2_destroy(d);
  client_key_destroy(client_key);
  return EXIT_SUCCESS;
}

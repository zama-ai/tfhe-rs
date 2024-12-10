#include "tfhe.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

int cpk_use_case(Config *config) {
  int ok = 0;

  // First, we create a ClientKey and a CompactPublicKey
  ClientKey *client_key = NULL;
  ServerKey *server_key = NULL;
  CompactPublicKey *public_key = NULL;
  {
    ok = generate_keys(config, &client_key, &server_key);
    assert(ok == 0);

    ok = set_server_key(server_key);
    assert(ok == 0);

    ok = compact_public_key_new(client_key, &public_key);
    assert(ok == 0);
  }

  // Then, we create the compact list
  CompactCiphertextList *compact_list = NULL;
  {
    CompactCiphertextListBuilder *builder;
    ok = compact_ciphertext_list_builder_new(public_key, &builder);
    assert(ok == 0);

    // Push some values
    ok = compact_ciphertext_list_builder_push_u32(builder, 38382);
    assert(ok == 0);

    ok = compact_ciphertext_list_builder_push_i64(builder, -1);
    assert(ok == 0);

    ok = compact_ciphertext_list_builder_push_bool(builder, true);
    assert(ok == 0);

    ok = compact_ciphertext_list_builder_push_u2(builder, 3);
    assert(ok == 0);

    ok = compact_ciphertext_list_builder_build(builder, &compact_list);
    assert(ok == 0);

    // Don't forget to destroy the builder
    compact_ciphertext_list_builder_destroy(builder);
  }

  // Now we can expand values
  FheUint32 *a = NULL;
  FheInt64 *b = NULL;
  FheBool *c = NULL;
  FheUint2 *d = NULL;
  {
    FheTypes type = Type_FheBool;
    CompactCiphertextListExpander *expander = NULL;

    ok = compact_ciphertext_list_expand(compact_list, &expander);
    assert(ok == 0);

    size_t len = 0;
    ok = compact_ciphertext_list_expander_len(expander, &len);
    assert(ok == 0 && len == 4);

    // First, an example of getting the type in a slot
    ok = compact_ciphertext_list_expander_get_kind_of(expander, 0, &type);
    assert(ok == 0 && type == Type_FheUint32);

    ok = compact_ciphertext_list_expander_get_kind_of(expander, 1, &type);
    assert(ok == 0 && type == Type_FheInt64);

    ok = compact_ciphertext_list_expander_get_kind_of(expander, 2, &type);
    assert(ok == 0 && type == Type_FheBool);

    ok = compact_ciphertext_list_expander_get_kind_of(expander, 3, &type);
    assert(ok == 0 && type == Type_FheUint2);

    // Then how to get the values
    ok = compact_ciphertext_list_expander_get_fhe_uint32(expander, 0, &a);
    assert(ok == 0);

    ok = compact_ciphertext_list_expander_get_fhe_int64(expander, 1, &b);
    assert(ok == 0);

    ok = compact_ciphertext_list_expander_get_fhe_bool(expander, 2, &c);
    assert(ok == 0);

    ok = compact_ciphertext_list_expander_get_fhe_uint2(expander, 3, &d);
    assert(ok == 0);

    // Don't forget to destroy the expander
    compact_ciphertext_list_expander_destroy(expander);
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
  server_key_destroy(server_key);
  compact_public_key_destroy(public_key);
  compact_ciphertext_list_destroy(compact_list);

  return ok;
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
    int ok = cpk_use_case(config);
    assert(ok == 0);
  }
  {
    ConfigBuilder *builder;
    Config *config;
    ok = config_builder_default(&builder);
    assert(ok == 0);
    ok = config_builder_use_custom_parameters(
        &builder, SHORTINT_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
    assert(ok == 0);
    ok = use_dedicated_compact_public_key_parameters(
        &builder, SHORTINT_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64);
    assert(ok == 0);
    ok = config_builder_build(builder, &config);
    assert(ok == 0);
    int ok = cpk_use_case(config);
    assert(ok == 0);
  }

  return EXIT_SUCCESS;
}

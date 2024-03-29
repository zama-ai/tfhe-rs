#include <tfhe.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

#ifdef WITH_FORWARD_COMPATIBILITY
int uint8_format_update(const ClientKey *client_key, const ServerKey *server_key) {
  int ok;
  FheUint8 *lhs = NULL;
  FheUint8 *deserialized_lhs = NULL;
  FheUint8 *result = NULL;
  DynamicBuffer value_buffer = {.pointer = NULL, .length = 0, .destructor = NULL};
  DynamicBuffer conformant_value_buffer = {.pointer = NULL, .length = 0, .destructor = NULL};
  DynamicBuffer cks_buffer = {.pointer = NULL, .length = 0, .destructor = NULL};
  DynamicBufferView deser_view = {.pointer = NULL, .length = 0};
  ClientKey *deserialized_client_key = NULL;
  DynamicBuffer out_buffer = {.pointer = NULL, .length = 0, .destructor = NULL};

  const uint64_t max_serialization_size = UINT64_C(1) << UINT64_C(20);

  uint8_t lhs_clear = 123;

  ok = client_key_serialize(client_key, &cks_buffer);
  assert(ok == 0);

  deser_view.pointer = cks_buffer.pointer;
  deser_view.length = cks_buffer.length;

  ok = client_key_update_serialization_from_0_5_to_0_6(deser_view, &out_buffer);
  assert(ok == 0);

  destroy_dynamic_buffer(&out_buffer);

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

  ok = fhe_uint8_update_serialization_from_0_5_to_0_6(deser_view, &out_buffer);
  assert(ok == 0);

  destroy_dynamic_buffer(&out_buffer);

  ok = fhe_uint8_safe_serialize(lhs, &conformant_value_buffer, max_serialization_size);
  assert(ok == 0);

  deser_view.pointer = conformant_value_buffer.pointer;
  deser_view.length = conformant_value_buffer.length;

  ok = fhe_uint8_safe_update_serialization_conformant_from_0_5_to_0_6(
      deser_view, max_serialization_size, server_key, &out_buffer);
  assert(ok == 0);

  destroy_dynamic_buffer(&out_buffer);

  deser_view.pointer = value_buffer.pointer;
  deser_view.length = value_buffer.length;
  ok = fhe_uint8_deserialize(deser_view, &deserialized_lhs);
  assert(ok == 0);

  uint8_t clear;
  ok = fhe_uint8_decrypt(deserialized_lhs, deserialized_client_key, &clear);
  assert(ok == 0);

  assert(clear == lhs_clear);

  destroy_dynamic_buffer(&value_buffer);
  destroy_dynamic_buffer(&conformant_value_buffer);

  fhe_uint8_destroy(lhs);
  fhe_uint8_destroy(deserialized_lhs);
  fhe_uint8_destroy(result);
  return ok;
}
#endif

int main(void) {
  int ok = 0;

#ifdef WITH_FORWARD_COMPATIBILITY
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
    ok = uint8_format_update(client_key, server_key);

    client_key_destroy(client_key);
    public_key_destroy(public_key);
    server_key_destroy(server_key);
  }
#endif

  return ok;
}

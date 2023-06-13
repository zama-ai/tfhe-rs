#include <tfhe.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

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

  ok = fhe_uint8_add(lhs, rhs, &result);
  assert(ok == 0);

  uint8_t clear;
  ok = fhe_uint8_decrypt(result, client_key, &clear);
  assert(ok == 0);

  assert(clear == (lhs_clear + rhs_clear));

  fhe_uint8_destroy(lhs);
  fhe_uint8_destroy(rhs);
  fhe_uint8_destroy(result);
  return ok;
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

int uint8_serialization(const ClientKey *client_key) {
  int ok;
  FheUint8 *lhs = NULL;
  FheUint8 *deserialized_lhs = NULL;
  FheUint8 *result = NULL;
  Buffer value_buffer = {.pointer = NULL, .length = 0};
  Buffer cks_buffer = {.pointer = NULL, .length = 0};
  BufferView deser_view = {.pointer = NULL, .length = 0};
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
    destroy_buffer(&value_buffer);
  }
  fhe_uint8_destroy(lhs);
  fhe_uint8_destroy(deserialized_lhs);
  fhe_uint8_destroy(result);
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
  fhe_uint8_destroy(result);
  return ok;
}

int main(void) {
  int ok = 0;
  {
    ConfigBuilder *builder;
    Config *config;

    ok = config_builder_all_disabled(&builder);
    assert(ok == 0);
    ok = config_builder_enable_default_integers(&builder);
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
    ok = uint8_compressed(client_key);
    assert(ok == 0);

    ok = set_server_key(server_key);
    assert(ok == 0);

    ok = uint8_client_key(client_key);
    assert(ok == 0);
    ok = uint8_public_key(client_key, public_key);
    assert(ok == 0);

    client_key_destroy(client_key);
    public_key_destroy(public_key);
    server_key_destroy(server_key);
  }

  {
    ConfigBuilder *builder;
    Config *config;

    ok = config_builder_all_disabled(&builder);
    assert(ok == 0);
    ok = config_builder_enable_default_integers_small(&builder);
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

    ok = set_server_key(server_key);
    assert(ok == 0);

    ok = uint8_client_key(client_key);
    assert(ok == 0);
    ok = uint8_public_key(client_key, public_key);
    assert(ok == 0);

    client_key_destroy(client_key);
    public_key_destroy(public_key);
    server_key_destroy(server_key);
  }

  return ok;
}

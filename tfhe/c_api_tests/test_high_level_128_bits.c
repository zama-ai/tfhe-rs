#include <tfhe.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

int uint128_client_key(const ClientKey *client_key) {
  int ok;
  FheUint128 *lhs = NULL;
  FheUint128 *rhs = NULL;
  FheUint128 *result = NULL;
  U128 lhs_clear = {10, 20};
  U128 rhs_clear = {1, 2};
  U128 result_clear = {0};

  ok = fhe_uint128_try_encrypt_with_client_key_u128(lhs_clear, client_key, &lhs);
  assert(ok == 0);

  ok = fhe_uint128_try_encrypt_with_client_key_u128(rhs_clear, client_key, &rhs);
  assert(ok == 0);

  ok = fhe_uint128_sub(lhs, rhs, &result);
  assert(ok == 0);

  ok = fhe_uint128_decrypt(result, client_key, &result_clear);
  assert(ok == 0);

  assert(result_clear.w0 == 9);
  assert(result_clear.w1 == 18);

  fhe_uint128_destroy(lhs);
  fhe_uint128_destroy(rhs);
  fhe_uint128_destroy(result);
  return ok;
}

int uint128_encrypt_trivial(const ClientKey *client_key) {
  int ok;
  FheUint128 *lhs = NULL;
  FheUint128 *rhs = NULL;
  FheUint128 *result = NULL;
  U128 lhs_clear = {10, 20};
  U128 rhs_clear = {1, 2};
  U128 result_clear = {0};

  ok = fhe_uint128_try_encrypt_trivial_u128(lhs_clear, &lhs);
  assert(ok == 0);

  ok = fhe_uint128_try_encrypt_trivial_u128(rhs_clear, &rhs);
  assert(ok == 0);

  ok = fhe_uint128_sub(lhs, rhs, &result);
  assert(ok == 0);

  ok = fhe_uint128_decrypt(result, client_key, &result_clear);
  assert(ok == 0);

  assert(result_clear.w0 == 9);
  assert(result_clear.w1 == 18);

  fhe_uint128_destroy(lhs);
  fhe_uint128_destroy(rhs);
  fhe_uint128_destroy(result);
  return ok;
}

int uint128_public_key(const ClientKey *client_key, const PublicKey *public_key) {
  int ok;
  FheUint128 *lhs = NULL;
  FheUint128 *rhs = NULL;
  FheUint128 *result = NULL;
  U128 lhs_clear = {10, 20};
  U128 rhs_clear = {1, 2};
  U128 result_clear = {0};

  ok = fhe_uint128_try_encrypt_with_public_key_u128(lhs_clear, public_key, &lhs);
  assert(ok == 0);

  ok = fhe_uint128_try_encrypt_with_public_key_u128(rhs_clear, public_key, &rhs);
  assert(ok == 0);

  ok = fhe_uint128_add(lhs, rhs, &result);
  assert(ok == 0);

  ok = fhe_uint128_decrypt(result, client_key, &result_clear);
  assert(ok == 0);

  assert(result_clear.w0 == 11);
  assert(result_clear.w1 == 22);

  fhe_uint128_destroy(lhs);
  fhe_uint128_destroy(rhs);
  fhe_uint128_destroy(result);
  return ok;
}

int main(void) {
  int ok = 0;
  ConfigBuilder *builder;
  Config *config;

  config_builder_all_disabled(&builder);
  config_builder_enable_default_integers_small(&builder);
  config_builder_build(builder, &config);

  ClientKey *client_key = NULL;
  ServerKey *server_key = NULL;
  PublicKey *public_key = NULL;

  generate_keys(config, &client_key, &server_key);
  public_key_new(client_key, &public_key);

  set_server_key(server_key);

  uint128_client_key(client_key);
  uint128_encrypt_trivial(client_key);
  uint128_public_key(client_key, public_key);

  client_key_destroy(client_key);
  public_key_destroy(public_key);
  server_key_destroy(server_key);
  return ok;
}

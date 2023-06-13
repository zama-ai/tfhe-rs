#include <tfhe.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

int uint256_client_key(const ClientKey *client_key) {
  int ok;
  FheUint256 *lhs = NULL;
  FheUint256 *rhs = NULL;
  FheUint256 *result = NULL;
  FheUint64 *cast_result = NULL;
  U256 lhs_clear = {1, 2, 3, 4};
  U256 rhs_clear = {5, 6, 7, 8};
  U256 result_clear = {0};

  ok = fhe_uint256_try_encrypt_with_client_key_u256(lhs_clear, client_key, &lhs);
  assert(ok == 0);

  ok = fhe_uint256_try_encrypt_with_client_key_u256(rhs_clear, client_key, &rhs);
  assert(ok == 0);

  ok = fhe_uint256_add(lhs, rhs, &result);
  assert(ok == 0);

  ok = fhe_uint256_decrypt(result, client_key, &result_clear);
  assert(ok == 0);

  assert(result_clear.w0 == 6);
  assert(result_clear.w1 == 8);
  assert(result_clear.w2 == 10);
  assert(result_clear.w3 == 12);

  // try some casting
  ok = fhe_uint256_cast_into_fhe_uint64(result, &cast_result);
  assert(ok == 0);
  uint64_t u64_clear;
  ok = fhe_uint64_decrypt(cast_result, client_key, &u64_clear);
  assert(ok == 0);
  assert(u64_clear == 6);

  fhe_uint256_destroy(lhs);
  fhe_uint256_destroy(rhs);
  fhe_uint256_destroy(result);
  fhe_uint64_destroy(cast_result);
  return ok;
}

int uint256_encrypt_trivial(const ClientKey *client_key) {
  int ok;
  FheUint256 *lhs = NULL;
  FheUint256 *rhs = NULL;
  FheUint256 *result = NULL;
  U256 lhs_clear = {1, 2, 3, 4};
  U256 rhs_clear = {5, 6, 7, 8};
  U256 result_clear = {0};

  ok = fhe_uint256_try_encrypt_trivial_u256(lhs_clear, &lhs);
  assert(ok == 0);

  ok = fhe_uint256_try_encrypt_trivial_u256(rhs_clear, &rhs);
  assert(ok == 0);

  ok = fhe_uint256_add(lhs, rhs, &result);
  assert(ok == 0);

  ok = fhe_uint256_decrypt(result, client_key, &result_clear);
  assert(ok == 0);

  assert(result_clear.w0 == 6);
  assert(result_clear.w1 == 8);
  assert(result_clear.w2 == 10);
  assert(result_clear.w3 == 12);

  fhe_uint256_destroy(lhs);
  fhe_uint256_destroy(rhs);
  fhe_uint256_destroy(result);
  return ok;
}

int uint256_public_key(const ClientKey *client_key, const PublicKey *public_key) {
  int ok;
  FheUint256 *lhs = NULL;
  FheUint256 *rhs = NULL;
  FheUint256 *result = NULL;
  U256 lhs_clear = {5, 6, 7, 8};
  U256 rhs_clear = {1, 2, 3, 4};
  U256 result_clear = {0};

  ok = fhe_uint256_try_encrypt_with_public_key_u256(lhs_clear, public_key, &lhs);
  assert(ok == 0);

  ok = fhe_uint256_try_encrypt_with_public_key_u256(rhs_clear, public_key, &rhs);
  assert(ok == 0);

  ok = fhe_uint256_sub(lhs, rhs, &result);
  assert(ok == 0);

  ok = fhe_uint256_decrypt(result, client_key, &result_clear);
  assert(ok == 0);

  assert(result_clear.w0 == 4);
  assert(result_clear.w1 == 4);
  assert(result_clear.w2 == 4);
  assert(result_clear.w3 == 4);

  fhe_uint256_destroy(lhs);
  fhe_uint256_destroy(rhs);
  fhe_uint256_destroy(result);
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

  uint256_client_key(client_key);
  uint256_encrypt_trivial(client_key);
  uint256_public_key(client_key, public_key);

  client_key_destroy(client_key);
  public_key_destroy(public_key);
  server_key_destroy(server_key);
  return ok;
}

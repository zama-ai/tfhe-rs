#include <tfhe.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

int uint2048_client_key(const ClientKey *client_key) {
  int ok;
  FheUint2048 *lhs = NULL;
  FheUint2048 *rhs = NULL;
  FheBool *result = NULL;
  FheUint64 *cast_result = NULL;
  U2048 lhs_clear = {.words = {0}};
  U2048 rhs_clear = {.words = {0}};
  bool result_clear = true;

  for (size_t i = 0; i < 32; ++i) {
    lhs_clear.words[i] = i;
    rhs_clear.words[i] = UINT64_MAX - i;
  }

  ok = fhe_uint2048_try_encrypt_with_client_key_u2048(lhs_clear, client_key, &lhs);
  assert(ok == 0);

  ok = fhe_uint2048_try_encrypt_with_client_key_u2048(rhs_clear, client_key, &rhs);
  assert(ok == 0);

  ok = fhe_uint2048_eq(lhs, rhs, &result);
  assert(ok == 0);

  ok = fhe_bool_decrypt(result, client_key, &result_clear);
  assert(ok == 0);

  assert(result_clear == false);

  fhe_uint2048_destroy(lhs);
  fhe_uint2048_destroy(rhs);
  fhe_bool_destroy(result);
  return ok;
}

int main(void) {
  int ok = 0;
  ConfigBuilder *builder;
  Config *config;

  config_builder_default(&builder);
  config_builder_build(builder, &config);

  ClientKey *client_key = NULL;
  ServerKey *server_key = NULL;
  PublicKey *public_key = NULL;

  generate_keys(config, &client_key, &server_key);
  public_key_new(client_key, &public_key);

  set_server_key(server_key);

  uint2048_client_key(client_key);

  client_key_destroy(client_key);
  public_key_destroy(public_key);
  server_key_destroy(server_key);
  return ok;
}

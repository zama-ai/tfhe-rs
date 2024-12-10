// If this test break the c_api doc needs to be updated

#include "tfhe.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void) {
  tfhe_error_disable_automatic_prints();

  int ok = 0;
  // Prepare the config builder for the high level API and choose which types to enable
  ConfigBuilder *builder;
  Config *config;

  config_builder_default(&builder);
  config_builder_build(builder, &config);

  ClientKey *client_key = NULL;
  ServerKey *server_key = NULL;

  generate_keys(config, &client_key, &server_key);

  // Intentionally forget the set_server_key to test error
  //  set_server_key(server_key);

  FheUint128 *lhs = NULL;
  FheUint128 *rhs = NULL;
  FheUint128 *result = NULL;

  U128 clear_lhs = {.w0 = 10, .w1 = 20};
  U128 clear_rhs = {.w0 = 1, .w1 = 2};

  ok = fhe_uint128_try_encrypt_with_client_key_u128(clear_lhs, client_key, &lhs);
  assert(ok == 0);

  ok = fhe_uint128_try_encrypt_with_client_key_u128(clear_rhs, client_key, &rhs);
  assert(ok == 0);

  const char *last_error = tfhe_error_get_last();
  assert(last_error != NULL);
  assert(strcmp(last_error, "no error") == 0);

  // Compute the subtraction
  ok = fhe_uint128_sub(lhs, rhs, &result);
  assert(ok == 1);

  last_error = tfhe_error_get_last();
  assert(last_error != NULL);
  printf("Error message Received from tfhe-rs: '%s'\n", last_error);

  // Destroy the ciphertexts
  fhe_uint128_destroy(lhs);
  fhe_uint128_destroy(rhs);

  // Destroy the keys
  client_key_destroy(client_key);
  server_key_destroy(server_key);

  return EXIT_SUCCESS;
}

// If this test break the c_api doc needs to be updated

#include "tfhe.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
  int ok = 0;
  // Prepare the config builder for the high level API and choose which types to enable
  ConfigBuilder *builder;
  Config *config;

  // Put the builder in a default state without any types enabled
  config_builder_default(&builder);
  // Populate the config
  config_builder_build(builder, &config);

  ClientKey *client_key = NULL;
  ServerKey *server_key = NULL;

  // Generate the keys using the config
  generate_keys(config, &client_key, &server_key);
  // Set the server key for the current thread
  set_server_key(server_key);

  FheUint128 *lhs = NULL;
  FheUint128 *rhs = NULL;
  FheUint128 *result = NULL;
  // A 128-bit unsigned integer containing value: 20 << 64 | 10
  U128 clear_lhs = {.w0 = 10, .w1 = 20};
  // A 128-bit unsigned integer containing value: 2 << 64 | 1
  U128 clear_rhs = {.w0 = 1, .w1 = 2};

  ok = fhe_uint128_try_encrypt_with_client_key_u128(clear_lhs, client_key, &lhs);
  assert(ok == 0);

  ok = fhe_uint128_try_encrypt_with_client_key_u128(clear_rhs, client_key, &rhs);
  assert(ok == 0);

  // Compute the subtraction
  ok = fhe_uint128_sub(lhs, rhs, &result);
  assert(ok == 0);

  U128 clear_result;
  // Decrypt
  ok = fhe_uint128_decrypt(result, client_key, &clear_result);
  assert(ok == 0);

  // Here the subtraction allows us to compare each word
  assert(clear_result.w0 == 9);
  assert(clear_result.w1 == 18);

  // Destroy the ciphertexts
  fhe_uint128_destroy(lhs);
  fhe_uint128_destroy(rhs);
  fhe_uint128_destroy(result);

  // Destroy the keys
  client_key_destroy(client_key);
  server_key_destroy(server_key);

  printf("FHE computation successful!\n");
  return EXIT_SUCCESS;
}

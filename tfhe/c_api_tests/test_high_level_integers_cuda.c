#if defined(WITH_FEATURE_GPU)
#include "tfhe.h"

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
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
    CompressedServerKey *compressed_sks = NULL;
    CudaServerKey *cuda_server_key = NULL;

    ok = client_key_generate(config, &client_key);
    assert(ok == 0);

    ok = compressed_server_key_new(client_key, &compressed_sks);
    assert(ok == 0);

    ok = compressed_server_key_decompress_to_gpu(compressed_sks, &cuda_server_key);
    assert(ok == 0);

    ok = set_cuda_server_key(cuda_server_key);
    assert(ok == 0);

    uint8_client_key(client_key);

    client_key_destroy(client_key);
    compressed_server_key_destroy(compressed_sks);
    cuda_server_key_destroy(cuda_server_key);
  }

  return ok;
}

#else
#include <stdio.h>

int main(void) {
  fputs("tfhe-rs was not compiled with gpu support\n", stdout);
  return 0;
}
#endif

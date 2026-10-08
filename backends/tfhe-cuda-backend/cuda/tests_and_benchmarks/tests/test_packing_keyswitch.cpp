#include "checked_arithmetic.h"
#include "device.h"
#include <cstdint>
#include <cstdlib>
#include <gtest/gtest.h>
#include <setup_and_teardown.h>
#include <vector>

typedef struct {
  int lwe_dimension;
  int glwe_dimension;
  int polynomial_size;
  DynamicDistribution lwe_noise_distribution;
  DynamicDistribution pksk_noise_distribution;
  int pksk_base_log;
  int pksk_level;
  int message_modulus;
  int carry_modulus;
  int num_lwes;
} PackingKeyswitchTestParams;

// Encryption / decryption / key generation for the two torus widths of the
// packing keyswitch. The C API is 64-bit only, so the 128-bit input LWEs are
// 64-bit ones modulus switched up (exact) and the 128-bit GLWE is modulus
// switched down before decryption (small rounding error).
static void encrypt_lwe(uint64_t *ct, uint64_t pt, const uint64_t *sk, int dim,
                        DynamicDistribution noise, Seed *seed) {
  core_crypto_lwe_encrypt(ct, pt, sk, dim, noise, seed->lo, seed->hi);
}
static void encrypt_lwe(__uint128_t *ct, __uint128_t pt, const uint64_t *sk,
                        int dim, DynamicDistribution noise, Seed *seed) {
  std::vector<uint64_t> ct_64(dim + 1);
  core_crypto_lwe_encrypt(ct_64.data(), (uint64_t)(pt >> 64), sk, dim, noise,
                          seed->lo, seed->hi);
  for (int i = 0; i <= dim; i++)
    ct[i] = (__uint128_t)ct_64[i] << 64;
}
static void decrypt_glwe(uint64_t *pt, const uint64_t *ct, const uint64_t *sk,
                         int glwe_dimension, int polynomial_size) {
  core_crypto_glwe_decrypt(pt, ct, sk, glwe_dimension, polynomial_size);
}
static void decrypt_glwe(__uint128_t *pt, const __uint128_t *ct,
                         const uint64_t *sk, int glwe_dimension,
                         int polynomial_size) {
  size_t glwe_size = (size_t)(glwe_dimension + 1) * polynomial_size;
  std::vector<uint64_t> ct_64(glwe_size);
  for (size_t i = 0; i < glwe_size; i++)
    ct_64[i] = (uint64_t)(ct[i] >> 64);
  std::vector<uint64_t> pt_64(polynomial_size);
  core_crypto_glwe_decrypt(pt_64.data(), ct_64.data(), sk, glwe_dimension,
                           polynomial_size);
  for (int i = 0; i < polynomial_size; i++)
    pt[i] = (__uint128_t)pt_64[i] << 64;
}
static void generate_pksk(cudaStream_t stream, uint32_t gpu_index,
                          uint64_t **d_pksk, uint64_t *lwe_sk,
                          uint64_t *glwe_sk, int lwe_dimension,
                          int glwe_dimension, int polynomial_size, int level,
                          int base_log, DynamicDistribution noise) {
  generate_lwe_packing_keyswitch_keys(stream, gpu_index, d_pksk, lwe_sk,
                                      glwe_sk, lwe_dimension, glwe_dimension,
                                      polynomial_size, level, base_log, noise);
}
static void generate_pksk(cudaStream_t stream, uint32_t gpu_index,
                          __uint128_t **d_pksk, uint64_t *lwe_sk,
                          uint64_t *glwe_sk, int lwe_dimension,
                          int glwe_dimension, int polynomial_size, int level,
                          int base_log, DynamicDistribution noise) {
  generate_lwe_packing_keyswitch_keys_128(
      stream, gpu_index, d_pksk, lwe_sk, glwe_sk, lwe_dimension, glwe_dimension,
      polynomial_size, level, base_log, noise);
}

template <typename Torus>
class PackingKeyswitchTestPrimitives
    : public ::testing::TestWithParam<PackingKeyswitchTestParams> {
protected:
  int lwe_dimension;
  int glwe_dimension;
  int polynomial_size;
  DynamicDistribution lwe_noise_distribution;
  DynamicDistribution pksk_noise_distribution;
  int pksk_base_log;
  int pksk_level;
  int message_modulus;
  int carry_modulus;
  int num_lwes;
  int payload_modulus;
  Torus delta;
  cudaStream_t stream;
  uint32_t gpu_index = 0;
  uint64_t *lwe_sk_in_array;
  uint64_t *glwe_sk_out_array;
  std::vector<Torus> plaintexts;
  Torus *d_pksk_array;
  Torus *d_lwe_ct_in_array;
  Torus *d_glwe_ct_out;
  int8_t *fp_ks_buffer = nullptr;

  // Decrypts the packed GLWE and checks that coefficient j holds the message
  // of LWE j, and 0 past the number of packed LWEs.
  void check_packed_glwe() {
    size_t glwe_size = (size_t)(glwe_dimension + 1) * polynomial_size;
    std::vector<Torus> glwe_out(glwe_size);
    cuda_memcpy_async_to_cpu(glwe_out.data(), d_glwe_ct_out,
                             safe_mul_sizeof<Torus>(glwe_size), stream,
                             gpu_index);
    cuda_synchronize_stream(stream, gpu_index);

    std::vector<Torus> decrypted(polynomial_size);
    decrypt_glwe(decrypted.data(), glwe_out.data(), glwe_sk_out_array,
                 glwe_dimension, polynomial_size);
    for (int j = 0; j < polynomial_size; j++) {
      Torus expected = j < num_lwes ? plaintexts[j] : (Torus)0;
      Torus rounding_bit = delta >> 1;
      Torus rounding = (decrypted[j] & rounding_bit) << 1;
      Torus decoded = (decrypted[j] + rounding) / delta;
      EXPECT_EQ((uint64_t)decoded, (uint64_t)(expected / delta))
          << "coefficient " << j;
    }
  }

public:
  void SetUp() {
    stream = cuda_create_stream(gpu_index);

    lwe_dimension = GetParam().lwe_dimension;
    glwe_dimension = GetParam().glwe_dimension;
    polynomial_size = GetParam().polynomial_size;
    lwe_noise_distribution = GetParam().lwe_noise_distribution;
    pksk_noise_distribution = GetParam().pksk_noise_distribution;
    pksk_base_log = GetParam().pksk_base_log;
    pksk_level = GetParam().pksk_level;
    message_modulus = GetParam().message_modulus;
    carry_modulus = GetParam().carry_modulus;
    num_lwes = GetParam().num_lwes;
    // One GEMM row tile is enough under compute-sanitizer.
    if (is_sanitizer_run())
      num_lwes = std::min(num_lwes, 32);

    payload_modulus = message_modulus * carry_modulus;
    delta = ((Torus)1 << (8 * sizeof(Torus) - 1)) / (Torus)payload_modulus;

    Seed seed;
    init_seed(&seed);
    shuffle_seed(&seed);
    generate_lwe_secret_keys(&lwe_sk_in_array, lwe_dimension, &seed, 1);
    shuffle_seed(&seed);
    generate_lwe_secret_keys(&glwe_sk_out_array,
                             glwe_dimension * polynomial_size, &seed, 1);
    generate_pksk(stream, gpu_index, &d_pksk_array, lwe_sk_in_array,
                  glwe_sk_out_array, lwe_dimension, glwe_dimension,
                  polynomial_size, pksk_level, pksk_base_log,
                  pksk_noise_distribution);

    // One input LWE per packed coefficient, each with a random message.
    size_t lwe_size = (size_t)lwe_dimension + 1;
    std::vector<Torus> lwe_ct_in(lwe_size * num_lwes);
    plaintexts.resize(num_lwes);
    for (int i = 0; i < num_lwes; i++) {
      plaintexts[i] = (Torus)(rand() % payload_modulus) * delta;
      shuffle_seed(&seed);
      encrypt_lwe(lwe_ct_in.data() + i * lwe_size, plaintexts[i],
                  lwe_sk_in_array, lwe_dimension, lwe_noise_distribution,
                  &seed);
    }
    d_lwe_ct_in_array = (Torus *)cuda_malloc_async(
        safe_mul_sizeof<Torus>(lwe_size, num_lwes), stream, gpu_index);
    cuda_memcpy_async_to_gpu(d_lwe_ct_in_array, lwe_ct_in.data(),
                             safe_mul_sizeof<Torus>(lwe_size, num_lwes), stream,
                             gpu_index);
    d_glwe_ct_out = (Torus *)cuda_malloc_async(
        safe_mul_sizeof<Torus>(glwe_dimension + 1, polynomial_size), stream,
        gpu_index);
    cuda_synchronize_stream(stream, gpu_index);
  }

  void TearDown() {
    cuda_synchronize_stream(stream, gpu_index);
    free(lwe_sk_in_array);
    free(glwe_sk_out_array);
    cuda_drop_async(d_pksk_array, stream, gpu_index);
    cuda_drop_async(d_lwe_ct_in_array, stream, gpu_index);
    cuda_drop_async(d_glwe_ct_out, stream, gpu_index);
    cuda_synchronize_stream(stream, gpu_index);
    cuda_destroy_stream(stream, gpu_index);
  }
};

using PackingKeyswitchTestPrimitives_u64 =
    PackingKeyswitchTestPrimitives<uint64_t>;
using PackingKeyswitchTestPrimitives_u128 =
    PackingKeyswitchTestPrimitives<__uint128_t>;

TEST_P(PackingKeyswitchTestPrimitives_u64, packing_keyswitch) {
  scratch_cuda_packing_keyswitch_lwe_list_to_glwe_64_async(
      stream, gpu_index, &fp_ks_buffer, lwe_dimension, glwe_dimension,
      polynomial_size, num_lwes, true);
  cuda_packing_keyswitch_lwe_list_to_glwe_64_async(
      stream, gpu_index, (void *)d_glwe_ct_out, (void *)d_lwe_ct_in_array,
      (void *)d_pksk_array, fp_ks_buffer, lwe_dimension, glwe_dimension,
      polynomial_size, pksk_base_log, pksk_level, num_lwes);
  check_packed_glwe();
  cleanup_cuda_packing_keyswitch_lwe_list_to_glwe_64(stream, gpu_index,
                                                     &fp_ks_buffer, true);
}

TEST_P(PackingKeyswitchTestPrimitives_u128, packing_keyswitch) {
  scratch_cuda_packing_keyswitch_lwe_list_to_glwe_128_async(
      stream, gpu_index, &fp_ks_buffer, lwe_dimension, glwe_dimension,
      polynomial_size, num_lwes, true);
  cuda_packing_keyswitch_lwe_list_to_glwe_128_async(
      stream, gpu_index, (void *)d_glwe_ct_out, (void *)d_lwe_ct_in_array,
      (void *)d_pksk_array, fp_ks_buffer, lwe_dimension, glwe_dimension,
      polynomial_size, pksk_base_log, pksk_level, num_lwes);
  check_packed_glwe();
  cleanup_cuda_packing_keyswitch_lwe_list_to_glwe_128(stream, gpu_index,
                                                      &fp_ks_buffer, true);
}

// n, k, N, lwe_noise, pksk_noise, pksk_base_log, pksk_level, message_modulus,
// carry_modulus, num_lwes. The input LWEs are under the big key of the 2_2
// params (k * N = 2048) with its glwe noise.
::testing::internal::ParamGenerator<PackingKeyswitchTestParams>
    packing_ksk_params_u64 = ::testing::Values(
        // COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, partial and full
        // (lwe_per_glwe = 256) polynomial.
        (PackingKeyswitchTestParams){2048, 4, 256, new_t_uniform(17),
                                     new_t_uniform(43), 4, 3, 4, 4, 100},
        (PackingKeyswitchTestParams){2048, 4, 256, new_t_uniform(17),
                                     new_t_uniform(43), 4, 3, 4, 4, 256});

// The input LWEs are under the noise squashing GLWE key (k * N = 4096).
::testing::internal::ParamGenerator<PackingKeyswitchTestParams>
    packing_ksk_params_u128 = ::testing::Values(
        // NOISE_SQUASHING_COMP_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        // lwe_per_glwe = 128 and a full polynomial.
        (PackingKeyswitchTestParams){4096, 6, 1024, new_t_uniform(17),
                                     new_t_uniform(3), 41, 2, 4, 4, 128},
        (PackingKeyswitchTestParams){4096, 6, 1024, new_t_uniform(17),
                                     new_t_uniform(3), 41, 2, 4, 4, 1024});

std::string
printParamName(::testing::TestParamInfo<PackingKeyswitchTestParams> p) {
  PackingKeyswitchTestParams params = p.param;

  return "n_" + std::to_string(params.lwe_dimension) + "_k_" +
         std::to_string(params.glwe_dimension) + "_N_" +
         std::to_string(params.polynomial_size) + "_baselog_" +
         std::to_string(params.pksk_base_log) + "_level_" +
         std::to_string(params.pksk_level) + "_num_lwes_" +
         std::to_string(params.num_lwes);
}

INSTANTIATE_TEST_CASE_P(PackingKeyswitchInstantiation,
                        PackingKeyswitchTestPrimitives_u64,
                        packing_ksk_params_u64, printParamName);
INSTANTIATE_TEST_CASE_P(PackingKeyswitchInstantiation,
                        PackingKeyswitchTestPrimitives_u128,
                        packing_ksk_params_u128, printParamName);

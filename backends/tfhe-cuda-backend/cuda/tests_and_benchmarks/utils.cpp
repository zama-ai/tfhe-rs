#include <algorithm>
#include "pbs/programmable_bootstrap.h"
#include "pbs/programmable_bootstrap_multibit.h"
#include "pbs/programmable_bootstrap_testing.h"
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <device.h>
#include <functional>
#include <random>
#include <utils.h>
#include <vector>

#include "checked_arithmetic.h"

void init_seed(Seed *seed) {
  seed->lo = 0;
  seed->hi = 0;
}

void shuffle_seed(Seed *seed) {
  //  std::random_device rd;
  //  std::mt19937 gen(rd());
  //  std::uniform_int_distribution<unsigned long long> dis(
  //      std::numeric_limits<std::uint64_t>::min(),
  //      std::numeric_limits<std::uint64_t>::max());
  //
  //    seed.lo += dis(gen);
  //    seed.hi += dis(gen);

  // This is a more convenient solution for testing
  seed->lo += 1;
  seed->hi += 1;
}

// For each sample and repetition, create a plaintext
// The payload_modulus is the message modulus times the carry modulus
// (so the total message modulus)
uint64_t *generate_plaintexts(uint64_t payload_modulus, uint64_t delta,
                              int number_of_inputs, const unsigned repetitions,
                              const unsigned samples) {

  uint64_t *plaintext_array = (uint64_t *)malloc(safe_mul_sizeof<uint64_t>(
      repetitions, samples, number_of_inputs));
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<unsigned long long> dis(
      std::numeric_limits<std::uint64_t>::min(),
      std::numeric_limits<std::uint64_t>::max());
  for (uint r = 0; r < repetitions; r++) {
    for (uint s = 0; s < samples; s++) {
      for (int i = 0; i < number_of_inputs; i++) {
        plaintext_array[r * samples * number_of_inputs + s * number_of_inputs +
                        i] = (dis(gen) % payload_modulus) * delta;
      }
    }
  }
  return plaintext_array;
}

uint64_t *generate_identity_lut_pbs(int polynomial_size, int glwe_dimension,
                                    int message_modulus, int carry_modulus,
                                    std::function<uint64_t(uint64_t)> func) {
  // Modulus of the msg contained in the msg bits and operations buffer
  uint64_t modulus_sup = message_modulus * carry_modulus;

  // N/p = size of each box
  uint64_t box_size = polynomial_size / modulus_sup;

  // Value of the shift we multiply our messages by
  uint64_t delta = ((uint64_t)1 << 63) / (uint64_t)(modulus_sup);

  // Create the plaintext lut_pbs
  uint64_t *plaintext_lut_pbs =
      (uint64_t *)malloc(safe_mul_sizeof<uint64_t>(polynomial_size));

  // This plaintext_lut_pbs extracts the carry bits
  for (uint64_t i = 0; i < modulus_sup; i++) {
    uint64_t index = i * box_size;
    for (uint64_t j = index; j < index + box_size; j++) {
      plaintext_lut_pbs[j] = func(i) * delta;
    }
  }

  uint64_t half_box_size = box_size / 2;

  // Negate the first half_box_size coefficients
  for (uint64_t i = 0; i < half_box_size; i++) {
    plaintext_lut_pbs[i] = -plaintext_lut_pbs[i];
  }

  // Rotate the plaintext_lut_pbs
  std::rotate(plaintext_lut_pbs, plaintext_lut_pbs + half_box_size,
              plaintext_lut_pbs + polynomial_size);

  // Create the GLWE lut_pbs
  uint64_t *lut_pbs = (uint64_t *)malloc(
      safe_mul_sizeof<uint64_t>(polynomial_size, glwe_dimension + 1));
  for (int i = 0; i < polynomial_size * glwe_dimension; i++) {
    lut_pbs[i] = 0;
  }
  for (int i = 0; i < polynomial_size; i++) {
    int glwe_index = glwe_dimension * polynomial_size + i;
    lut_pbs[glwe_index] = plaintext_lut_pbs[i];
  }

  free(plaintext_lut_pbs);
  return lut_pbs;
}

// Generate repetitions LWE secret keys
void generate_lwe_secret_keys(uint64_t **lwe_sk_array, int lwe_dimension,
                              Seed *seed, const unsigned repetitions) {
  *lwe_sk_array =
      (uint64_t *)malloc(safe_mul_sizeof<uint64_t>(lwe_dimension, repetitions));
  int shift = 0;
  for (uint r = 0; r < repetitions; r++) {
    // Generate the lwe secret key for each repetition
    core_crypto_lwe_secret_key(*lwe_sk_array + (ptrdiff_t)(shift),
                               lwe_dimension, seed->lo, seed->hi);
    shift += lwe_dimension;
  }
}

// Generate repetitions GLWE secret keys
void generate_glwe_secret_keys(uint64_t **glwe_sk_array, int glwe_dimension,
                               int polynomial_size, Seed *seed,
                               const unsigned repetitions) {
  size_t glwe_sk_array_size = safe_mul(glwe_dimension, polynomial_size, repetitions);
  *glwe_sk_array = (uint64_t *)malloc(safe_mul_sizeof<uint64_t>(glwe_sk_array_size));
  int shift = 0;
  for (uint r = 0; r < repetitions; r++) {
    // Generate the lwe secret key for each repetition
    core_crypto_lwe_secret_key(*glwe_sk_array + (ptrdiff_t)(shift),
                               glwe_dimension * polynomial_size, seed->lo,
                               seed->hi);
    shift += glwe_dimension * polynomial_size;
  }
}

// Generate repetitions LWE bootstrap keys
void generate_lwe_programmable_bootstrap_keys(cudaStream_t stream, uint32_t gpu_index,
                                 double **d_fourier_bsk_array,
                                 uint64_t *lwe_sk_in_array,
                                 uint64_t *lwe_sk_out_array, int lwe_dimension,
                                 int glwe_dimension, int polynomial_size,
                                 int pbs_level, int pbs_base_log, Seed *seed,
                                 DynamicDistribution noise_distribution,
                                 const unsigned repetitions) {
  size_t bsk_size = safe_mul(
      safe_mul(glwe_dimension + 1, glwe_dimension + 1, pbs_level,
                        polynomial_size),
      (size_t)(lwe_dimension + 1));
  size_t bsk_array_size = safe_mul(bsk_size, repetitions);

  uint64_t *bsk_array = (uint64_t *)malloc(safe_mul_sizeof<uint64_t>(bsk_array_size));
  *d_fourier_bsk_array =
      (double *)cuda_malloc_async(safe_mul_sizeof<double>(bsk_array_size), stream, gpu_index);
  int shift_in = 0;
  int shift_out = 0;
  int shift_bsk = 0;

  for (uint r = 0; r < repetitions; r++) {
    // Generate the bootstrap key for each repetition
    core_crypto_par_generate_lwe_bootstrapping_key(
        bsk_array + (ptrdiff_t)(shift_bsk), pbs_base_log, pbs_level,
        lwe_sk_in_array + (ptrdiff_t)(shift_in), lwe_dimension,
        lwe_sk_out_array + (ptrdiff_t)(shift_out), glwe_dimension,
        polynomial_size, noise_distribution, seed->lo, seed->hi);
    double *d_fourier_bsk = *d_fourier_bsk_array + (ptrdiff_t)(shift_bsk);
    uint64_t *bsk = bsk_array + (ptrdiff_t)(shift_bsk);
    cuda_synchronize_stream(stream, gpu_index);
    cuda_convert_lwe_programmable_bootstrap_key_64_async(stream, gpu_index, (void *)(d_fourier_bsk), (void *)(bsk),
                                      lwe_dimension, glwe_dimension,
                                      pbs_level, polynomial_size);
    shift_in += lwe_dimension;
    shift_out += glwe_dimension * polynomial_size;
    shift_bsk += bsk_size;
  }
  cuda_synchronize_stream(stream, gpu_index);
  free(bsk_array);
}

//Force the vanilla layout of the bsk for the classical TBC.
void generate_lwe_programmable_bootstrap_keys_standard(
    cudaStream_t stream, uint32_t gpu_index, double **d_fourier_bsk_array,
    uint64_t *lwe_sk_in_array, uint64_t *lwe_sk_out_array, int lwe_dimension,
    int glwe_dimension, int polynomial_size, int pbs_level, int pbs_base_log,
    Seed *seed, DynamicDistribution noise_distribution,
    const unsigned repetitions) {
  size_t bsk_size = safe_mul(
      safe_mul(glwe_dimension + 1, glwe_dimension + 1, pbs_level,
               polynomial_size),
      (size_t)(lwe_dimension + 1));
  size_t bsk_array_size = safe_mul(bsk_size, repetitions);

  uint64_t *bsk_array =
      (uint64_t *)malloc(safe_mul_sizeof<uint64_t>(bsk_array_size));
  *d_fourier_bsk_array = (double *)cuda_malloc_async(
      safe_mul_sizeof<double>(bsk_array_size), stream, gpu_index);
  int shift_in = 0;
  int shift_out = 0;
  int shift_bsk = 0;

  for (uint r = 0; r < repetitions; r++) {
    core_crypto_par_generate_lwe_bootstrapping_key(
        bsk_array + (ptrdiff_t)(shift_bsk), pbs_base_log, pbs_level,
        lwe_sk_in_array + (ptrdiff_t)(shift_in), lwe_dimension,
        lwe_sk_out_array + (ptrdiff_t)(shift_out), glwe_dimension,
        polynomial_size, noise_distribution, seed->lo, seed->hi);
    double *d_fourier_bsk = *d_fourier_bsk_array + (ptrdiff_t)(shift_bsk);
    uint64_t *bsk = bsk_array + (ptrdiff_t)(shift_bsk);
    cuda_synchronize_stream(stream, gpu_index);
    cuda_convert_lwe_programmable_bootstrap_key_standard_64_async(
        stream, gpu_index, (void *)(d_fourier_bsk), (void *)(bsk),
        lwe_dimension, glwe_dimension, pbs_level, polynomial_size);
    shift_in += lwe_dimension;
    shift_out += glwe_dimension * polynomial_size;
    shift_bsk += bsk_size;
  }
  cuda_synchronize_stream(stream, gpu_index);
  free(bsk_array);
}

// Use the bsk layout required by the specialized 2_2 classical PBS kernel.
void generate_lwe_programmable_bootstrap_keys_specialized_2_2(
    cudaStream_t stream, uint32_t gpu_index, double **d_fourier_bsk_array,
    uint64_t *lwe_sk_in_array, uint64_t *lwe_sk_out_array, int lwe_dimension,
    int glwe_dimension, int polynomial_size, int pbs_level, int pbs_base_log,
    Seed *seed, DynamicDistribution noise_distribution,
    const unsigned repetitions) {
  size_t bsk_size = safe_mul(
      safe_mul(glwe_dimension + 1, glwe_dimension + 1, pbs_level,
               polynomial_size),
      (size_t)(lwe_dimension + 1));
  size_t bsk_array_size = safe_mul(bsk_size, repetitions);

  uint64_t *bsk_array =
      (uint64_t *)malloc(safe_mul_sizeof<uint64_t>(bsk_array_size));
  *d_fourier_bsk_array = (double *)cuda_malloc_async(
      safe_mul_sizeof<double>(bsk_array_size), stream, gpu_index);
  int shift_in = 0;
  int shift_out = 0;
  int shift_bsk = 0;

  for (uint r = 0; r < repetitions; r++) {
    core_crypto_par_generate_lwe_bootstrapping_key(
        bsk_array + (ptrdiff_t)(shift_bsk), pbs_base_log, pbs_level,
        lwe_sk_in_array + (ptrdiff_t)(shift_in), lwe_dimension,
        lwe_sk_out_array + (ptrdiff_t)(shift_out), glwe_dimension,
        polynomial_size, noise_distribution, seed->lo, seed->hi);
    double *d_fourier_bsk = *d_fourier_bsk_array + (ptrdiff_t)(shift_bsk);
    uint64_t *bsk = bsk_array + (ptrdiff_t)(shift_bsk);
    cuda_synchronize_stream(stream, gpu_index);
    // Use forced-specialized BSK conversion (CC bypass) so the BSK layout
    // matches what the specialized kernel (device_programmable_bootstrap_
    // specialized_2_2_params) expects.
    cuda_convert_lwe_programmable_bootstrap_key_specialized_2_2_64_async(
        stream, gpu_index, (void *)(d_fourier_bsk), (void *)(bsk),
        lwe_dimension, glwe_dimension, pbs_level, polynomial_size);
    shift_in += lwe_dimension;
    shift_out += glwe_dimension * polynomial_size;
    shift_bsk += bsk_size;
  }
  cuda_synchronize_stream(stream, gpu_index);
  free(bsk_array);
}

// Use the bsk layout required by the throughput oriented 2_2 classical PBS
// kernel (H100 only).
void generate_lwe_programmable_bootstrap_keys_specialized_2_2_throughput(
    cudaStream_t stream, uint32_t gpu_index, double **d_fourier_bsk_array,
    uint64_t *lwe_sk_in_array, uint64_t *lwe_sk_out_array, int lwe_dimension,
    int glwe_dimension, int polynomial_size, int pbs_level, int pbs_base_log,
    Seed *seed, DynamicDistribution noise_distribution,
    const unsigned repetitions) {
  size_t bsk_size = safe_mul(
      safe_mul(glwe_dimension + 1, glwe_dimension + 1, pbs_level,
               polynomial_size),
      (size_t)(lwe_dimension + 1));
  size_t bsk_array_size = safe_mul(bsk_size, repetitions);

  uint64_t *bsk_array =
      (uint64_t *)malloc(safe_mul_sizeof<uint64_t>(bsk_array_size));
  *d_fourier_bsk_array = (double *)cuda_malloc_async(
      safe_mul_sizeof<double>(bsk_array_size), stream, gpu_index);
  int shift_in = 0;
  int shift_out = 0;
  int shift_bsk = 0;

  for (uint r = 0; r < repetitions; r++) {
    core_crypto_par_generate_lwe_bootstrapping_key(
        bsk_array + (ptrdiff_t)(shift_bsk), pbs_base_log, pbs_level,
        lwe_sk_in_array + (ptrdiff_t)(shift_in), lwe_dimension,
        lwe_sk_out_array + (ptrdiff_t)(shift_out), glwe_dimension,
        polynomial_size, noise_distribution, seed->lo, seed->hi);
    double *d_fourier_bsk = *d_fourier_bsk_array + (ptrdiff_t)(shift_bsk);
    uint64_t *bsk = bsk_array + (ptrdiff_t)(shift_bsk);
    cuda_synchronize_stream(stream, gpu_index);
    cuda_convert_lwe_programmable_bootstrap_key_specialized_2_2_throughput_64_async(
        stream, gpu_index, (void *)(d_fourier_bsk), (void *)(bsk),
        lwe_dimension, glwe_dimension, pbs_level, polynomial_size);
    shift_in += lwe_dimension;
    shift_out += glwe_dimension * polynomial_size;
    shift_bsk += bsk_size;
  }
  cuda_synchronize_stream(stream, gpu_index);
  free(bsk_array);
}

void generate_lwe_multi_bit_programmable_bootstrap_keys(
    cudaStream_t stream, uint32_t gpu_index, uint64_t **d_bsk_array, uint64_t *lwe_sk_in_array,
    uint64_t *lwe_sk_out_array, int lwe_dimension, int glwe_dimension,
    int polynomial_size, int grouping_factor, int pbs_level, int pbs_base_log,
    DynamicDistribution noise_distribution,
    const unsigned repetitions) {

  // Multiply all factors first, then divide by grouping_factor at the end
  // to preserve integer division semantics (the full product is always
  // divisible by grouping_factor, but partial sub-products may not be)
  size_t bsk_size =
      safe_mul(
          safe_mul((size_t)lwe_dimension, (size_t)pbs_level,
                            (size_t)(glwe_dimension + 1),
                            (size_t)(glwe_dimension + 1)),
          safe_mul((size_t)polynomial_size,
                            (size_t)(1 << grouping_factor))) /
      grouping_factor;
  size_t bsk_array_size = safe_mul(bsk_size, repetitions);
  uint64_t *bsk_array = (uint64_t *)malloc(safe_mul_sizeof<uint64_t>(bsk_array_size));

  *d_bsk_array =
      (uint64_t *)cuda_malloc_async(safe_mul_sizeof<uint64_t>(bsk_array_size), stream, gpu_index);
  for (uint r = 0; r < repetitions; r++) {
    int shift_in = 0;
    int shift_out = 0;
    int shift_bsk = 0;
    core_crypto_par_generate_lwe_multi_bit_bootstrapping_key(
        lwe_sk_in_array + (ptrdiff_t)(shift_in), lwe_dimension,
        lwe_sk_out_array + (ptrdiff_t)(shift_out), glwe_dimension,
        polynomial_size, bsk_array + (ptrdiff_t)(shift_bsk), pbs_base_log,
        pbs_level, grouping_factor, noise_distribution, 0, 0);
    uint64_t *d_bsk = *d_bsk_array + (ptrdiff_t)(shift_bsk);
    uint64_t *bsk = bsk_array + (ptrdiff_t)(shift_bsk);
    cuda_convert_lwe_multi_bit_programmable_bootstrap_key_64_async(
        stream, gpu_index, d_bsk, bsk, lwe_dimension, glwe_dimension, pbs_level,
        polynomial_size, grouping_factor);
    shift_in += lwe_dimension;
    shift_out += glwe_dimension * polynomial_size;
    shift_bsk += bsk_size;
  }
  cuda_synchronize_stream(stream, gpu_index);
  free(bsk_array);
}

// Generate repetitions keyswitch keys
void generate_lwe_keyswitch_keys(
    cudaStream_t stream, uint32_t gpu_index, uint64_t **d_ksk_array, uint64_t *lwe_sk_in_array,
    uint64_t *lwe_sk_out_array, int input_lwe_dimension,
    int output_lwe_dimension, int ksk_level, int ksk_base_log, Seed *seed,
    DynamicDistribution noise_distribution, const unsigned repetitions) {

  size_t ksk_size = safe_mul(ksk_level, output_lwe_dimension + 1, input_lwe_dimension);
  size_t ksk_array_size = safe_mul(ksk_size, repetitions);

  uint64_t *ksk_array = (uint64_t *)malloc(safe_mul_sizeof<uint64_t>(ksk_array_size));
  *d_ksk_array =
      (uint64_t *)cuda_malloc_async(safe_mul_sizeof<uint64_t>(ksk_array_size), stream, gpu_index);
  int shift_in = 0;
  int shift_out = 0;
  int shift_ksk = 0;

  for (uint r = 0; r < repetitions; r++) {
    // Generate the keyswitch key for each repetition
    core_crypto_par_generate_lwe_keyswitch_key(
        ksk_array + (ptrdiff_t)(shift_ksk), ksk_base_log, ksk_level,
        lwe_sk_in_array + (ptrdiff_t)(shift_in), input_lwe_dimension,
        lwe_sk_out_array + (ptrdiff_t)(shift_out), output_lwe_dimension,
        noise_distribution, seed->lo, seed->hi);
    uint64_t *d_ksk = *d_ksk_array + (ptrdiff_t)(shift_ksk);
    uint64_t *ksk = ksk_array + (ptrdiff_t)(shift_ksk);
    cuda_memcpy_async_to_gpu(d_ksk, ksk, safe_mul_sizeof<uint64_t>(ksk_size), stream, gpu_index);

    shift_in += input_lwe_dimension;
    shift_out += output_lwe_dimension;
    shift_ksk += ksk_size;
  }
  cuda_synchronize_stream(stream, gpu_index);
  free(ksk_array);
}

// The C API only generates 64-bit keyswitch keys. The 64 -> 32 flavors read a
// 32-bit ksk, obtained here by modulus switching the 64-bit one.
void generate_lwe_keyswitch_keys_u32(
    cudaStream_t stream, uint32_t gpu_index, uint32_t **d_ksk_array,
    uint64_t *lwe_sk_in_array, uint64_t *lwe_sk_out_array,
    int input_lwe_dimension, int output_lwe_dimension, int ksk_level,
    int ksk_base_log, Seed *seed, DynamicDistribution noise_distribution,
    const unsigned repetitions) {

  size_t ksk_size =
      safe_mul(ksk_level, output_lwe_dimension + 1, input_lwe_dimension);
  size_t ksk_array_size = safe_mul(ksk_size, repetitions);

  uint64_t *ksk_array =
      (uint64_t *)malloc(safe_mul_sizeof<uint64_t>(ksk_array_size));
  uint32_t *ksk_array_u32 =
      (uint32_t *)malloc(safe_mul_sizeof<uint32_t>(ksk_array_size));
  *d_ksk_array = (uint32_t *)cuda_malloc_async(
      safe_mul_sizeof<uint32_t>(ksk_array_size), stream, gpu_index);
  int shift_in = 0;
  int shift_out = 0;
  int shift_ksk = 0;

  for (uint r = 0; r < repetitions; r++) {
    core_crypto_par_generate_lwe_keyswitch_key(
        ksk_array + (ptrdiff_t)(shift_ksk), ksk_base_log, ksk_level,
        lwe_sk_in_array + (ptrdiff_t)(shift_in), input_lwe_dimension,
        lwe_sk_out_array + (ptrdiff_t)(shift_out), output_lwe_dimension,
        noise_distribution, seed->lo, seed->hi);
    shift_in += input_lwe_dimension;
    shift_out += output_lwe_dimension;
    shift_ksk += ksk_size;
  }
  for (size_t i = 0; i < ksk_array_size; i++)
    ksk_array_u32[i] = (uint32_t)(ksk_array[i] >> 32);
  cuda_memcpy_async_to_gpu(*d_ksk_array, ksk_array_u32,
                           safe_mul_sizeof<uint32_t>(ksk_array_size), stream,
                           gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
  free(ksk_array);
  free(ksk_array_u32);
}

// The C API has no packing keyswitch key generator and is 64-bit only, so the
// test builds the key itself: GLWE encryptions of s_i * B^-l with monomial
// masks, which turn the mask times key products into rotations, and uniform
// noise in [-2^b, 2^b] with b from the t_uniform distribution.
template <typename Torus>
static std::vector<Torus> generate_lwe_packing_keyswitch_key_host(
    uint64_t *lwe_sk_in_array, uint64_t *glwe_sk_out_array, int lwe_dimension,
    int glwe_dimension, int polynomial_size, int pksk_level, int pksk_base_log,
    DynamicDistribution noise_distribution) {
  // Only the t_uniform tag is supported here.
  PANIC_IF_FALSE(noise_distribution.tag == 1,
                 "packing keyswitch key generation needs a t_uniform noise");
  const uint32_t bound_log2 =
      noise_distribution.distribution.t_uniform.bound_log2;
  const int torus_bits = 8 * sizeof(Torus);
  static std::mt19937_64 rng(0);
  auto random_torus = [&]() {
    Torus r = rng();
    if (sizeof(Torus) > 8)
      r = (r << 32 << 32) | (Torus)rng();
    return r;
  };

  size_t glwe_size = safe_mul(glwe_dimension + 1, polynomial_size);
  std::vector<Torus> pksk(safe_mul(lwe_dimension, pksk_level, glwe_size));
  Torus *block = pksk.data();
  for (int i = 0; i < lwe_dimension; i++) {
    // Blocks go from the highest level down to 1, as in the Rust key layout.
    for (int l = pksk_level; l >= 1; l--, block += glwe_size) {
      Torus *body = block + glwe_dimension * polynomial_size;
      for (int t = 0; t < polynomial_size; t++)
        body[t] = (Torus)(rng() % ((1ull << (bound_log2 + 1)) + 1)) -
                  ((Torus)1 << bound_log2);
      body[0] += (Torus)lwe_sk_in_array[i]
                 << (torus_bits - pksk_base_log * l);
      for (int j = 0; j < glwe_dimension; j++) {
        const uint64_t *sk = glwe_sk_out_array + j * polynomial_size;
        Torus r = random_torus();
        int d = rng() % polynomial_size;
        block[j * polynomial_size + d] = r;
        // body += r * X^d * S_j, negacyclic
        for (int t = 0; t < polynomial_size; t++) {
          Torus s = r * (Torus)sk[(t - d + polynomial_size) % polynomial_size];
          body[t] += t >= d ? s : -s;
        }
      }
    }
  }
  return pksk;
}

template <typename Torus>
static void upload_lwe_packing_keyswitch_keys(
    cudaStream_t stream, uint32_t gpu_index, Torus **d_pksk_array,
    uint64_t *lwe_sk_in_array, uint64_t *glwe_sk_out_array, int lwe_dimension,
    int glwe_dimension, int polynomial_size, int pksk_level, int pksk_base_log,
    DynamicDistribution noise_distribution) {
  std::vector<Torus> pksk = generate_lwe_packing_keyswitch_key_host<Torus>(
      lwe_sk_in_array, glwe_sk_out_array, lwe_dimension, glwe_dimension,
      polynomial_size, pksk_level, pksk_base_log, noise_distribution);
  size_t pksk_bytes = safe_mul_sizeof<Torus>(pksk.size());
  *d_pksk_array = (Torus *)cuda_malloc_async(pksk_bytes, stream, gpu_index);
  cuda_memcpy_async_to_gpu(*d_pksk_array, pksk.data(), pksk_bytes, stream,
                           gpu_index);
  cuda_synchronize_stream(stream, gpu_index);
}

void generate_lwe_packing_keyswitch_keys(
    cudaStream_t stream, uint32_t gpu_index, uint64_t **d_pksk_array,
    uint64_t *lwe_sk_in_array, uint64_t *glwe_sk_out_array, int lwe_dimension,
    int glwe_dimension, int polynomial_size, int pksk_level, int pksk_base_log,
    DynamicDistribution noise_distribution) {
  upload_lwe_packing_keyswitch_keys<uint64_t>(
      stream, gpu_index, d_pksk_array, lwe_sk_in_array, glwe_sk_out_array,
      lwe_dimension, glwe_dimension, polynomial_size, pksk_level,
      pksk_base_log, noise_distribution);
}

void generate_lwe_packing_keyswitch_keys_128(
    cudaStream_t stream, uint32_t gpu_index, __uint128_t **d_pksk_array,
    uint64_t *lwe_sk_in_array, uint64_t *glwe_sk_out_array, int lwe_dimension,
    int glwe_dimension, int polynomial_size, int pksk_level, int pksk_base_log,
    DynamicDistribution noise_distribution) {
  upload_lwe_packing_keyswitch_keys<__uint128_t>(
      stream, gpu_index, d_pksk_array, lwe_sk_in_array, glwe_sk_out_array,
      lwe_dimension, glwe_dimension, polynomial_size, pksk_level,
      pksk_base_log, noise_distribution);
}

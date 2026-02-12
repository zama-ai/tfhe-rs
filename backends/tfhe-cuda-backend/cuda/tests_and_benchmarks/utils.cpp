#include <algorithm>
#include "pbs/programmable_bootstrap.h"
#include "pbs/programmable_bootstrap_multibit.h"
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <device.h>
#include <functional>
#include <random>
#include <utils.h>

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

  // N/(p/2) = size of each block
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
    cuda_convert_lwe_programmable_bootstrap_key_64(stream, gpu_index, (void *)(d_fourier_bsk), (void *)(bsk),
                                      lwe_dimension, glwe_dimension,
                                      pbs_level, polynomial_size);
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
    cuda_convert_lwe_multi_bit_programmable_bootstrap_key_64(
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

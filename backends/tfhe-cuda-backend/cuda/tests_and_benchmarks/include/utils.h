#ifndef UTILS_H
#define UTILS_H

#include "tfhe.h"
#include <device.h>
#include <functional>

typedef struct Seed {
  uint64_t lo;
  uint64_t hi;
} Seed;

void init_seed(Seed *seed);

void shuffle_seed(Seed *seed);

uint64_t *generate_plaintexts(uint64_t payload_modulus, uint64_t delta,
                              int number_of_inputs, const unsigned repetitions,
                              const unsigned samples);

uint64_t *generate_identity_lut_pbs(int polynomial_size, int glwe_dimension,
                                    int message_modulus, int carry_modulus,
                                    std::function<uint64_t(uint64_t)> func);

void generate_lwe_secret_keys(uint64_t **lwe_sk_array, int lwe_dimension,
                              Seed *seed, const unsigned repetitions);

void generate_glwe_secret_keys(uint64_t **glwe_sk_array, int glwe_dimension,
                               int polynomial_size, Seed *seed,
                               const unsigned repetitions);

void generate_lwe_programmable_bootstrap_keys(
    cudaStream_t stream, uint32_t gpu_index, double **d_fourier_bsk_array,
    uint64_t *lwe_sk_in_array, uint64_t *lwe_sk_out_array, int lwe_dimension,
    int glwe_dimension, int polynomial_size, int pbs_level, int pbs_base_log,
    Seed *seed, DynamicDistribution noise_distribution,
    const unsigned repetitions);

void generate_lwe_multi_bit_programmable_bootstrap_keys(
    cudaStream_t stream, uint32_t gpu_index, uint64_t **d_bsk_array,
    uint64_t *lwe_sk_in_array, uint64_t *lwe_sk_out_array, int lwe_dimension,
    int glwe_dimension, int polynomial_size, int pbs_level, int pbs_base_log,
    int grouping_factor, DynamicDistribution noise_distribution,
    const unsigned repetitions);

void generate_lwe_keyswitch_keys(
    cudaStream_t stream, uint32_t gpu_index, uint64_t **d_ksk_array,
    uint64_t *lwe_sk_in_array, uint64_t *lwe_sk_out_array,
    int input_lwe_dimension, int output_lwe_dimension, int ksk_level,
    int ksk_base_log, Seed *seed, DynamicDistribution noise_distribution,
    const unsigned repetitions);

#endif

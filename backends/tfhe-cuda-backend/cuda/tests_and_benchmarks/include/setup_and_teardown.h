#ifndef SETUP_AND_TEARDOWN_H
#define SETUP_AND_TEARDOWN_H

#include "pbs/programmable_bootstrap.h"
#include "pbs/programmable_bootstrap_multibit.h"
#include <device.h>
#include <keyswitch.h>
#include <utils.h>

void programmable_bootstrap_classical_setup(
    cudaStream_t stream, uint32_t gpu_index, Seed *seed,
    uint64_t **lwe_sk_in_array, uint64_t **lwe_sk_out_array,
    double **d_fourier_bsk_array, uint64_t **plaintexts,
    uint64_t **d_lut_pbs_identity, uint64_t **d_lut_pbs_indexes,
    uint64_t **d_lwe_ct_in_array, uint64_t **d_lwe_input_indexes,
    uint64_t **d_lwe_ct_out_array, uint64_t **d_lwe_output_indexes,
    int lwe_dimension, int glwe_dimension, int polynomial_size,
    DynamicDistribution lwe_noise_distribution,
    DynamicDistribution glwe_noise_distribution, int pbs_base_log,
    int pbs_level, int message_modulus, int carry_modulus, int *payload_modulus,
    uint64_t *delta, int number_of_inputs, int repetitions, int samples);
void programmable_bootstrap_classical_teardown(
    cudaStream_t stream, uint32_t gpu_index, uint64_t *lwe_sk_in_array,
    uint64_t *lwe_sk_out_array, double *d_fourier_bsk_array,
    uint64_t *plaintexts, uint64_t *d_lut_pbs_identity,
    uint64_t *d_lut_pbs_indexes, uint64_t *d_lwe_ct_in_array,
    uint64_t *d_lwe_input_indexes, uint64_t *d_lwe_ct_out_array,
    uint64_t *d_lwe_output_indexes);
void programmable_bootstrap_multibit_setup(
    cudaStream_t stream, uint32_t gpu_index, Seed *seed,
    uint64_t **lwe_sk_in_array, uint64_t **lwe_sk_out_array,
    uint64_t **d_bsk_array, uint64_t **plaintexts,
    uint64_t **d_lut_pbs_identity, uint64_t **d_lut_pbs_indexes,
    uint64_t **d_lwe_ct_in_array, uint64_t **d_lwe_input_indexes,
    uint64_t **d_lwe_ct_out_array, uint64_t **d_lwe_output_indexes,
    int lwe_dimension, int glwe_dimension, int polynomial_size,
    int grouping_factor, DynamicDistribution lwe_noise_distribution,
    DynamicDistribution glwe_noise_distribution, int pbs_base_log,
    int pbs_level, int message_modulus, int carry_modulus, int *payload_modulus,
    uint64_t *delta, int number_of_inputs, int repetitions, int samples);
void programmable_bootstrap_multibit_teardown(
    cudaStream_t stream, uint32_t gpu_index, uint64_t *lwe_sk_in_array,
    uint64_t *lwe_sk_out_array, uint64_t *d_bsk_array, uint64_t *plaintexts,
    uint64_t *d_lut_pbs_identity, uint64_t *d_lut_pbs_indexes,
    uint64_t *d_lwe_ct_in_array, uint64_t *d_lwe_input_indexes,
    uint64_t *d_lwe_ct_out_array, uint64_t *d_lwe_output_indexes);
void keyswitch_setup(cudaStream_t stream, uint32_t gpu_index, Seed *seed,
                     uint64_t **lwe_sk_in_array, uint64_t **lwe_sk_out_array,
                     uint64_t **d_ksk_array, uint64_t **plaintexts,
                     uint64_t **d_lwe_ct_in_array,
                     uint64_t **d_lwe_input_indexes,
                     uint64_t **d_lwe_ct_out_array,
                     uint64_t **d_lwe_output_indexes, int input_lwe_dimension,
                     int output_lwe_dimension,
                     DynamicDistribution lwe_noise_distribution,
                     int ksk_base_log, int ksk_level, int message_modulus,
                     int carry_modulus, int *payload_modulus, uint64_t *delta,
                     int number_of_inputs, int repetitions, int samples);
void keyswitch_teardown(cudaStream_t stream, uint32_t gpu_index,
                        uint64_t *lwe_sk_in_array, uint64_t *lwe_sk_out_array,
                        uint64_t *d_ksk_array, uint64_t *plaintexts,
                        uint64_t *d_lwe_ct_in_array,
                        uint64_t *lwe_input_indexes,
                        uint64_t *d_lwe_ct_out_array,
                        uint64_t *lwe_output_indexes);

void fft_setup(cudaStream_t stream, uint32_t gpu_index, double **poly1,
               double **poly2, double2 **h_cpoly1, double2 **h_cpoly2,
               double2 **d_cpoly1, double2 **d_cpoly2, size_t polynomial_size,
               int samples);

void fft_teardown(cudaStream_t stream, uint32_t gpu_index, double *poly1,
                  double *poly2, double2 *h_cpoly1, double2 *h_cpoly2,
                  double2 *d_cpoly1, double2 *d_cpoly2);

#endif // SETUP_AND_TEARDOWN_H

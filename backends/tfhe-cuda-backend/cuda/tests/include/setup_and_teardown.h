#ifndef SETUP_AND_TEARDOWN_H
#define SETUP_AND_TEARDOWN_H

#include <bootstrap.h>
#include <bootstrap_multibit.h>
#include <device.h>
#include <keyswitch.h>
#include <utils.h>

void bootstrap_classical_setup(
    cuda_stream_t *stream, Seed *seed, uint64_t **lwe_sk_in_array,
    uint64_t **lwe_sk_out_array, double **d_fourier_bsk_array,
    uint64_t **plaintexts, uint64_t **d_lut_pbs_identity,
    uint64_t **d_lut_pbs_indexes, uint64_t **d_lwe_ct_in_array,
    uint64_t **d_lwe_input_indexes, uint64_t **d_lwe_ct_out_array,
    uint64_t **d_lwe_output_indexes, int lwe_dimension, int glwe_dimension,
    int polynomial_size, double lwe_modular_variance,
    double glwe_modular_variance, int pbs_base_log, int pbs_level,
    int message_modulus, int carry_modulus, int *payload_modulus,
    uint64_t *delta, int number_of_inputs, int repetitions, int samples);
void bootstrap_classical_teardown(
    cuda_stream_t *stream, uint64_t *lwe_sk_in_array,
    uint64_t *lwe_sk_out_array, double *d_fourier_bsk_array,
    uint64_t *plaintexts, uint64_t *d_lut_pbs_identity,
    uint64_t *d_lut_pbs_indexes, uint64_t *d_lwe_ct_in_array,
    uint64_t *d_lwe_input_indexes, uint64_t *d_lwe_ct_out_array,
    uint64_t *d_lwe_output_indexes);
void bootstrap_multibit_setup(
    cuda_stream_t *stream, Seed *seed, uint64_t **lwe_sk_in_array,
    uint64_t **lwe_sk_out_array, uint64_t **d_bsk_array, uint64_t **plaintexts,
    uint64_t **d_lut_pbs_identity, uint64_t **d_lut_pbs_indexes,
    uint64_t **d_lwe_ct_in_array, uint64_t **d_lwe_input_indexes,
    uint64_t **d_lwe_ct_out_array, uint64_t **d_lwe_output_indexes,
    int8_t **pbs_buffer, int lwe_dimension, int glwe_dimension,
    int polynomial_size, int grouping_factor, double lwe_modular_variance,
    double glwe_modular_variance, int pbs_base_log, int pbs_level,
    int message_modulus, int carry_modulus, int *payload_modulus,
    uint64_t *delta, int number_of_inputs, int repetitions, int samples,
    int chunk_size = 0);
void bootstrap_multibit_teardown(
    cuda_stream_t *stream, uint64_t *lwe_sk_in_array,
    uint64_t *lwe_sk_out_array, uint64_t *d_bsk_array, uint64_t *plaintexts,
    uint64_t *d_lut_pbs_identity, uint64_t *d_lut_pbs_indexes,
    uint64_t *d_lwe_ct_in_array, uint64_t *d_lwe_input_indexes,
    uint64_t *d_lwe_ct_out_array, uint64_t *d_lwe_output_indexes,
    int8_t **pbs_buffer);
void keyswitch_setup(cuda_stream_t *stream, Seed *seed,
                     uint64_t **lwe_sk_in_array, uint64_t **lwe_sk_out_array,
                     uint64_t **d_ksk_array, uint64_t **plaintexts,
                     uint64_t **d_lwe_ct_in_array,
                     uint64_t **d_lwe_input_indexes,
                     uint64_t **d_lwe_ct_out_array,
                     uint64_t **d_lwe_output_indexes, int input_lwe_dimension,
                     int output_lwe_dimension, double lwe_modular_variance,
                     int ksk_base_log, int ksk_level, int message_modulus,
                     int carry_modulus, int *payload_modulus, uint64_t *delta,
                     int number_of_inputs, int repetitions, int samples);
void keyswitch_teardown(cuda_stream_t *stream, uint64_t *lwe_sk_in_array,
                        uint64_t *lwe_sk_out_array, uint64_t *d_ksk_array,
                        uint64_t *plaintexts, uint64_t *d_lwe_ct_in_array,
                        uint64_t *lwe_input_indexes,
                        uint64_t *d_lwe_ct_out_array,
                        uint64_t *lwe_output_indexes);

void fft_setup(cuda_stream_t *stream, double **poly1, double **poly2,
               double2 **h_cpoly1, double2 **h_cpoly2, double2 **d_cpoly1,
               double2 **d_cpoly2, size_t polynomial_size, int samples);

void fft_teardown(cuda_stream_t *stream, double *poly1, double *poly2,
                  double2 *h_cpoly1, double2 *h_cpoly2, double2 *d_cpoly1,
                  double2 *d_cpoly2);

#endif // SETUP_AND_TEARDOWN_H

#include <cmath>
#include <random>
#include <setup_and_teardown.h>

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
    uint64_t *delta, int number_of_inputs, int repetitions, int samples) {

  *payload_modulus = message_modulus * carry_modulus;
  // Value of the shift we multiply our messages by
  *delta = ((uint64_t)(1) << 63) / (uint64_t)(*payload_modulus);

  // Generate the keys
  shuffle_seed(seed);
  generate_lwe_secret_keys(lwe_sk_in_array, lwe_dimension, seed, repetitions);
  shuffle_seed(seed);
  generate_lwe_secret_keys(lwe_sk_out_array, glwe_dimension * polynomial_size,
                           seed, repetitions);
  shuffle_seed(seed);
  generate_lwe_bootstrap_keys(stream, d_fourier_bsk_array, *lwe_sk_in_array,
                              *lwe_sk_out_array, lwe_dimension, glwe_dimension,
                              polynomial_size, pbs_level, pbs_base_log, seed,
                              glwe_modular_variance, repetitions);
  shuffle_seed(seed);
  *plaintexts = generate_plaintexts(*payload_modulus, *delta, number_of_inputs,
                                    repetitions, samples);

  // Create the LUT
  uint64_t *lut_pbs_identity = generate_identity_lut_pbs(
      polynomial_size, glwe_dimension, message_modulus, carry_modulus,
      [](int x) -> int { return x; });
  uint64_t *lwe_ct_in_array =
      (uint64_t *)malloc((lwe_dimension + 1) * number_of_inputs * repetitions *
                         samples * sizeof(uint64_t));
  // Create the input/output ciphertexts
  for (int r = 0; r < repetitions; r++) {
    uint64_t *lwe_sk_in = *lwe_sk_in_array + (ptrdiff_t)(r * lwe_dimension);
    for (int s = 0; s < samples; s++) {
      for (int i = 0; i < number_of_inputs; i++) {
        uint64_t plaintext = (*plaintexts)[r * samples * number_of_inputs +
                                           s * number_of_inputs + i];
        uint64_t *lwe_ct_in =
            lwe_ct_in_array + (ptrdiff_t)((r * samples * number_of_inputs +
                                           s * number_of_inputs + i) *
                                          (lwe_dimension + 1));
        core_crypto_lwe_encrypt(lwe_ct_in, plaintext, lwe_sk_in, lwe_dimension,
                                lwe_modular_variance, seed->lo, seed->hi);
        shuffle_seed(seed);
      }
    }
  }

  // Initialize and copy things in/to the device
  *d_lut_pbs_identity = (uint64_t *)cuda_malloc_async(
      (glwe_dimension + 1) * polynomial_size * sizeof(uint64_t), stream);
  cuda_memcpy_async_to_gpu(
      *d_lut_pbs_identity, lut_pbs_identity,
      polynomial_size * (glwe_dimension + 1) * sizeof(uint64_t), stream);
  *d_lut_pbs_indexes = (uint64_t *)cuda_malloc_async(
      number_of_inputs * sizeof(uint64_t), stream);
  cuda_memset_async(*d_lut_pbs_indexes, 0, number_of_inputs * sizeof(uint64_t),
                    stream);

  // Input and output LWEs
  *d_lwe_ct_out_array =
      (uint64_t *)cuda_malloc_async((glwe_dimension * polynomial_size + 1) *
                                        number_of_inputs * sizeof(uint64_t),
                                    stream);
  *d_lwe_ct_in_array = (uint64_t *)cuda_malloc_async(
      (lwe_dimension + 1) * number_of_inputs * repetitions * samples *
          sizeof(uint64_t),
      stream);

  cuda_memcpy_async_to_gpu(*d_lwe_ct_in_array, lwe_ct_in_array,
                           repetitions * samples * number_of_inputs *
                               (lwe_dimension + 1) * sizeof(uint64_t),
                           stream);

  uint64_t *h_lwe_indexes =
      (uint64_t *)malloc(number_of_inputs * sizeof(uint64_t));
  *d_lwe_input_indexes = (uint64_t *)cuda_malloc_async(
      number_of_inputs * sizeof(uint64_t), stream);
  *d_lwe_output_indexes = (uint64_t *)cuda_malloc_async(
      number_of_inputs * sizeof(uint64_t), stream);
  for (int i = 0; i < number_of_inputs; i++)
    h_lwe_indexes[i] = i;
  cuda_memcpy_async_to_gpu(*d_lwe_input_indexes, h_lwe_indexes,
                           number_of_inputs * sizeof(uint64_t), stream);
  cuda_memcpy_async_to_gpu(*d_lwe_output_indexes, h_lwe_indexes,
                           number_of_inputs * sizeof(uint64_t), stream);

  stream->synchronize();

  free(lwe_ct_in_array);
  free(lut_pbs_identity);
  free(h_lwe_indexes);
}

void bootstrap_classical_teardown(
    cuda_stream_t *stream, uint64_t *lwe_sk_in_array,
    uint64_t *lwe_sk_out_array, double *d_fourier_bsk_array,
    uint64_t *plaintexts, uint64_t *d_lut_pbs_identity,
    uint64_t *d_lut_pbs_indexes, uint64_t *d_lwe_ct_in_array,
    uint64_t *d_lwe_input_indexes, uint64_t *d_lwe_ct_out_array,
    uint64_t *d_lwe_output_indexes) {
  cuda_synchronize_stream(stream);

  free(lwe_sk_in_array);
  free(lwe_sk_out_array);
  free(plaintexts);

  cuda_drop_async(d_fourier_bsk_array, stream);
  cuda_drop_async(d_lut_pbs_identity, stream);
  cuda_drop_async(d_lut_pbs_indexes, stream);
  cuda_drop_async(d_lwe_ct_in_array, stream);
  cuda_drop_async(d_lwe_ct_out_array, stream);
  cuda_drop_async(d_lwe_input_indexes, stream);
  cuda_drop_async(d_lwe_output_indexes, stream);
  stream->synchronize();
  cuda_destroy_stream(stream);
}

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
    int lwe_chunk_size) {
  cudaSetDevice(stream->gpu_index);

  *payload_modulus = message_modulus * carry_modulus;
  // Value of the shift we multiply our messages by
  *delta = ((uint64_t)(1) << 63) / (uint64_t)(*payload_modulus);

  // Generate the keys
  shuffle_seed(seed);
  generate_lwe_secret_keys(lwe_sk_in_array, lwe_dimension, seed, repetitions);
  shuffle_seed(seed);
  generate_lwe_secret_keys(lwe_sk_out_array, glwe_dimension * polynomial_size,
                           seed, repetitions);
  shuffle_seed(seed);
  generate_lwe_multi_bit_pbs_keys(
      stream, d_bsk_array, *lwe_sk_in_array, *lwe_sk_out_array, lwe_dimension,
      glwe_dimension, polynomial_size, grouping_factor, pbs_level, pbs_base_log,
      seed, glwe_modular_variance, repetitions);
  shuffle_seed(seed);

  *plaintexts = generate_plaintexts(*payload_modulus, *delta, number_of_inputs,
                                    repetitions, samples);

  // Create the LUT
  uint64_t *lut_pbs_identity = generate_identity_lut_pbs(
      polynomial_size, glwe_dimension, message_modulus, carry_modulus,
      [](int x) -> int { return x; });
  uint64_t *lwe_ct_in_array =
      (uint64_t *)malloc((lwe_dimension + 1) * number_of_inputs * repetitions *
                         samples * sizeof(uint64_t));
  // Create the input/output ciphertexts
  for (int r = 0; r < repetitions; r++) {
    uint64_t *lwe_sk_in = *lwe_sk_in_array + (ptrdiff_t)(r * lwe_dimension);
    for (int s = 0; s < samples; s++) {
      for (int i = 0; i < number_of_inputs; i++) {
        uint64_t plaintext = (*plaintexts)[r * samples * number_of_inputs +
                                           s * number_of_inputs + i];
        uint64_t *lwe_ct_in =
            lwe_ct_in_array + (ptrdiff_t)((r * samples * number_of_inputs +
                                           s * number_of_inputs + i) *
                                          (lwe_dimension + 1));
        core_crypto_lwe_encrypt(lwe_ct_in, plaintext, lwe_sk_in, lwe_dimension,
                                lwe_modular_variance, seed->lo, seed->hi);
        shuffle_seed(seed);
      }
    }
  }

  // Initialize and copy things in/to the device
  *d_lut_pbs_identity = (uint64_t *)cuda_malloc_async(
      (glwe_dimension + 1) * polynomial_size * sizeof(uint64_t), stream);
  cuda_memcpy_async_to_gpu(
      *d_lut_pbs_identity, lut_pbs_identity,
      polynomial_size * (glwe_dimension + 1) * sizeof(uint64_t), stream);
  *d_lut_pbs_indexes = (uint64_t *)cuda_malloc_async(
      number_of_inputs * sizeof(uint64_t), stream);
  cuda_memset_async(*d_lut_pbs_indexes, 0, number_of_inputs * sizeof(uint64_t),
                    stream);

  // Input and output LWEs
  *d_lwe_ct_out_array =
      (uint64_t *)cuda_malloc_async((glwe_dimension * polynomial_size + 1) *
                                        number_of_inputs * sizeof(uint64_t),
                                    stream);
  *d_lwe_ct_in_array = (uint64_t *)cuda_malloc_async(
      (lwe_dimension + 1) * number_of_inputs * repetitions * samples *
          sizeof(uint64_t),
      stream);

  cuda_memcpy_async_to_gpu(*d_lwe_ct_in_array, lwe_ct_in_array,
                           repetitions * samples * number_of_inputs *
                               (lwe_dimension + 1) * sizeof(uint64_t),
                           stream);

  uint64_t *h_lwe_indexes =
      (uint64_t *)malloc(number_of_inputs * sizeof(uint64_t));
  *d_lwe_input_indexes = (uint64_t *)cuda_malloc_async(
      number_of_inputs * sizeof(uint64_t), stream);
  *d_lwe_output_indexes = (uint64_t *)cuda_malloc_async(
      number_of_inputs * sizeof(uint64_t), stream);
  for (int i = 0; i < number_of_inputs; i++)
    h_lwe_indexes[i] = i;
  cuda_memcpy_async_to_gpu(*d_lwe_input_indexes, h_lwe_indexes,
                           number_of_inputs * sizeof(uint64_t), stream);
  cuda_memcpy_async_to_gpu(*d_lwe_output_indexes, h_lwe_indexes,
                           number_of_inputs * sizeof(uint64_t), stream);

  scratch_cuda_multi_bit_pbs_64(
      stream, pbs_buffer, lwe_dimension, glwe_dimension, polynomial_size,
      pbs_level, grouping_factor, number_of_inputs,
      cuda_get_max_shared_memory(stream->gpu_index), true, lwe_chunk_size);

  stream->synchronize();

  free(h_lwe_indexes);
  free(lut_pbs_identity);
  free(lwe_ct_in_array);
}

void bootstrap_multibit_teardown(
    cuda_stream_t *stream, uint64_t *lwe_sk_in_array,
    uint64_t *lwe_sk_out_array, uint64_t *d_bsk_array, uint64_t *plaintexts,
    uint64_t *d_lut_pbs_identity, uint64_t *d_lut_pbs_indexes,
    uint64_t *d_lwe_ct_in_array, uint64_t *d_lwe_input_indexes,
    uint64_t *d_lwe_ct_out_array, uint64_t *d_lwe_output_indexes,
    int8_t **pbs_buffer) {
  cuda_synchronize_stream(stream);

  free(lwe_sk_in_array);
  free(lwe_sk_out_array);
  free(plaintexts);

  cleanup_cuda_multi_bit_pbs(stream, pbs_buffer);
  cuda_drop_async(d_bsk_array, stream);
  cuda_drop_async(d_lut_pbs_identity, stream);
  cuda_drop_async(d_lut_pbs_indexes, stream);
  cuda_drop_async(d_lwe_ct_in_array, stream);
  cuda_drop_async(d_lwe_ct_out_array, stream);
  cuda_drop_async(d_lwe_input_indexes, stream);
  cuda_drop_async(d_lwe_output_indexes, stream);
  stream->synchronize();
  cuda_destroy_stream(stream);
}

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
                     int number_of_inputs, int repetitions, int samples) {

  *payload_modulus = message_modulus * carry_modulus;
  // Value of the shift we multiply our messages by
  *delta = ((uint64_t)(1) << 63) / (uint64_t)(*payload_modulus);

  // Generate the keys
  shuffle_seed(seed);
  generate_lwe_secret_keys(lwe_sk_in_array, input_lwe_dimension, seed,
                           repetitions);
  shuffle_seed(seed);
  generate_lwe_secret_keys(lwe_sk_out_array, output_lwe_dimension, seed,
                           repetitions);
  shuffle_seed(seed);
  generate_lwe_keyswitch_keys(stream, d_ksk_array, *lwe_sk_in_array,
                              *lwe_sk_out_array, input_lwe_dimension,
                              output_lwe_dimension, ksk_level, ksk_base_log,
                              seed, lwe_modular_variance, repetitions);
  shuffle_seed(seed);
  *plaintexts = generate_plaintexts(*payload_modulus, *delta, number_of_inputs,
                                    repetitions, samples);

  *d_lwe_ct_out_array = (uint64_t *)cuda_malloc_async(
      (output_lwe_dimension + 1) * number_of_inputs * sizeof(uint64_t), stream);
  *d_lwe_ct_in_array = (uint64_t *)cuda_malloc_async(
      (input_lwe_dimension + 1) * number_of_inputs * repetitions * samples *
          sizeof(uint64_t),
      stream);
  uint64_t *lwe_ct_in_array =
      (uint64_t *)malloc((input_lwe_dimension + 1) * number_of_inputs *
                         repetitions * samples * sizeof(uint64_t));
  // Create the input/output ciphertexts
  for (int r = 0; r < repetitions; r++) {
    uint64_t *lwe_sk_in =
        *lwe_sk_in_array + (ptrdiff_t)(r * input_lwe_dimension);
    for (int s = 0; s < samples; s++) {
      for (int i = 0; i < number_of_inputs; i++) {
        uint64_t plaintext = (*plaintexts)[r * samples * number_of_inputs +
                                           s * number_of_inputs + i];
        uint64_t *lwe_ct_in =
            lwe_ct_in_array + (ptrdiff_t)((r * samples * number_of_inputs +
                                           s * number_of_inputs + i) *
                                          (input_lwe_dimension + 1));
        core_crypto_lwe_encrypt(lwe_ct_in, plaintext, lwe_sk_in,
                                input_lwe_dimension, lwe_modular_variance,
                                seed->lo, seed->hi);
        shuffle_seed(seed);
      }
    }
  }
  cuda_memcpy_async_to_gpu(*d_lwe_ct_in_array, lwe_ct_in_array,
                           repetitions * samples * number_of_inputs *
                               (input_lwe_dimension + 1) * sizeof(uint64_t),
                           stream);
  stream->synchronize();

  uint64_t *h_lwe_indexes =
      (uint64_t *)malloc(number_of_inputs * sizeof(uint64_t));
  *d_lwe_input_indexes = (uint64_t *)cuda_malloc_async(
      number_of_inputs * sizeof(uint64_t), stream);
  *d_lwe_output_indexes = (uint64_t *)cuda_malloc_async(
      number_of_inputs * sizeof(uint64_t), stream);
  for (int i = 0; i < number_of_inputs; i++)
    h_lwe_indexes[i] = i;
  cuda_memcpy_async_to_gpu(*d_lwe_input_indexes, h_lwe_indexes,
                           number_of_inputs * sizeof(uint64_t), stream);
  cuda_memcpy_async_to_gpu(*d_lwe_output_indexes, h_lwe_indexes,
                           number_of_inputs * sizeof(uint64_t), stream);

  cuda_synchronize_stream(stream);
  free(h_lwe_indexes);
  free(lwe_ct_in_array);
}

void keyswitch_teardown(cuda_stream_t *stream, uint64_t *lwe_sk_in_array,
                        uint64_t *lwe_sk_out_array, uint64_t *d_ksk_array,
                        uint64_t *plaintexts, uint64_t *d_lwe_ct_in_array,
                        uint64_t *d_lwe_input_indexes,
                        uint64_t *d_lwe_ct_out_array,
                        uint64_t *d_lwe_output_indexes) {
  cuda_synchronize_stream(stream);

  free(lwe_sk_in_array);
  free(lwe_sk_out_array);
  free(plaintexts);

  cuda_drop_async(d_ksk_array, stream);
  cuda_drop_async(d_lwe_ct_in_array, stream);
  cuda_drop_async(d_lwe_ct_out_array, stream);
  cuda_drop_async(d_lwe_input_indexes, stream);
  cuda_drop_async(d_lwe_output_indexes, stream);
  stream->synchronize();
  cuda_destroy_stream(stream);
}


void fft_setup(cuda_stream_t *stream, double **_poly1, double **_poly2,
               double2 **_h_cpoly1, double2 **_h_cpoly2, double2 **_d_cpoly1,
               double2 **_d_cpoly2, size_t polynomial_size, int samples) {

  auto &poly1 = *_poly1;
  auto &poly2 = *_poly2;
  auto &h_cpoly1 = *_h_cpoly1;
  auto &h_cpoly2 = *_h_cpoly2;
  auto &d_cpoly1 = *_d_cpoly1;
  auto &d_cpoly2 = *_d_cpoly2;

  poly1 = (double *)malloc(polynomial_size * samples * sizeof(double));
  poly2 = (double *)malloc(polynomial_size * samples * sizeof(double));
  h_cpoly1 = (double2 *)malloc(polynomial_size / 2 * samples * sizeof(double2));
  h_cpoly2 = (double2 *)malloc(polynomial_size / 2 * samples * sizeof(double2));
  d_cpoly1 = (double2 *)cuda_malloc_async(
      polynomial_size / 2 * samples * sizeof(double2), stream);
  d_cpoly2 = (double2 *)cuda_malloc_async(
      polynomial_size / 2 * samples * sizeof(double2), stream);

  double lower_bound = -1;
  double upper_bound = 1;
  std::uniform_real_distribution<double> unif(lower_bound, upper_bound);
  std::default_random_engine re;
  // Fill test data with random values
  for (size_t i = 0; i < polynomial_size * samples; i++) {
    poly1[i] = unif(re);
    poly2[i] = unif(re);
  }

  // prepare data for device
  // compress
  for (size_t p = 0; p < (size_t)samples; p++) {
    auto left_cpoly = &h_cpoly1[p * polynomial_size / 2];
    auto right_cpoly = &h_cpoly2[p * polynomial_size / 2];
    auto left = &poly1[p * polynomial_size];
    auto right = &poly2[p * polynomial_size];
    for (std::size_t i = 0; i < polynomial_size / 2; ++i) {
      left_cpoly[i].x = left[i];
      left_cpoly[i].y = left[i + polynomial_size / 2];

      right_cpoly[i].x = right[i];
      right_cpoly[i].y = right[i + polynomial_size / 2];
    }
  }

  // copy memory cpu->gpu
  cuda_memcpy_async_to_gpu(d_cpoly1, h_cpoly1,
                           polynomial_size / 2 * samples * sizeof(double2),
                           stream);
  cuda_memcpy_async_to_gpu(d_cpoly2, h_cpoly2,
                           polynomial_size / 2 * samples * sizeof(double2),
                           stream);
  stream->synchronize();
}

void fft_teardown(cuda_stream_t *stream, double *poly1, double *poly2,
                  double2 *h_cpoly1, double2 *h_cpoly2, double2 *d_cpoly1,
                  double2 *d_cpoly2) {
  stream->synchronize();

  free(poly1);
  free(poly2);
  free(h_cpoly1);
  free(h_cpoly2);

  cuda_drop_async(d_cpoly1, stream);
  cuda_drop_async(d_cpoly2, stream);
  stream->synchronize();
  cuda_destroy_stream(stream);
}

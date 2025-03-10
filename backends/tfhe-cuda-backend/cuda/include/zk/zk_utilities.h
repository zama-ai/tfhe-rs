//
// Created by pedro on 12/03/25.
//

#ifndef ZK_UTILITIES_H
#define ZK_UTILITIES_H

#include "../integer/integer_utilities.h"
#include "integer/integer.cuh"
#include <cstdint>

template <typename Torus> struct zk_expand {
  int_radix_params params;
  uint32_t num_lwes;

  int_radix_lut<Torus> *message_and_carry_extract_luts;
  // Booleans have to be sanitized
  int_radix_lut<Torus> *message_and_carry_extract_bool_luts;

  Torus *tmp_expanded_lwes;

  zk_expand(cudaStream_t const *streams, uint32_t const *gpu_indexes,
            uint32_t gpu_count, int_radix_params params, uint32_t num_lwes,
            bool allocate_gpu_memory)
      : params(params), num_lwes(num_lwes) {

    if (allocate_gpu_memory) {
      auto message_extract_lut_f = [params](Torus x) -> Torus {
        return x % params.message_modulus;
      };
      auto carry_extract_lut_f = [params](Torus x) -> Torus {
        return (x / params.carry_modulus) % params.message_modulus;
      };

      auto sanitize_bool_f = [](Torus x) -> Torus { return x == 0 ? 0 : 1; };
      auto message_extract_and_sanitize_bool_lut_f =
          [message_extract_lut_f, sanitize_bool_f](Torus x) -> Torus {
        return sanitize_bool_f(message_extract_lut_f(x));
      };
      auto carry_extract_and_sanitize_bool_lut_f =
          [carry_extract_lut_f, sanitize_bool_f](Torus x) -> Torus {
        return sanitize_bool_f(carry_extract_lut_f(x));
      };

      message_and_carry_extract_luts =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 2,
                                   2 * num_lwes, allocate_gpu_memory);

      message_and_carry_extract_bool_luts =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 2,
                                   2 * num_lwes, allocate_gpu_memory);

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0],
          message_and_carry_extract_luts->get_lut(0, 0),
          message_and_carry_extract_luts->get_degree(0),
          message_and_carry_extract_luts->get_max_degree(0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, message_extract_lut_f);

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0],
          message_and_carry_extract_luts->get_lut(0, 1),
          message_and_carry_extract_luts->get_degree(1),
          message_and_carry_extract_luts->get_max_degree(1),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, carry_extract_lut_f);

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0],
          message_and_carry_extract_bool_luts->get_lut(0, 0),
          message_and_carry_extract_bool_luts->get_degree(0),
          message_and_carry_extract_bool_luts->get_max_degree(0),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, message_extract_and_sanitize_bool_lut_f);

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0],
          message_and_carry_extract_bool_luts->get_lut(0, 1),
          message_and_carry_extract_bool_luts->get_degree(1),
          message_and_carry_extract_bool_luts->get_max_degree(1),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, carry_extract_and_sanitize_bool_lut_f);

      // Adjust indexes to permute the output and access the correct LUT
      auto h_indexes_in =
          static_cast<Torus *>(malloc(2 * num_lwes * sizeof(Torus)));
      auto h_indexes_out =
          static_cast<Torus *>(malloc(2 * num_lwes * sizeof(Torus)));
      auto h_lut_indexes =
          static_cast<Torus *>(malloc(2 * num_lwes * sizeof(Torus)));

      for (int i = 0; i < 2 * num_lwes; i++) {
        Torus j = i % num_lwes;
        h_indexes_in[i] = j;
        h_indexes_out[i] = (i < num_lwes) ? 2 * j : 2 * j + 1;
        h_lut_indexes[i] = i / num_lwes;
      }

      message_and_carry_extract_luts->set_lwe_indexes(
          streams[0], gpu_indexes[0], h_indexes_in, h_indexes_out);
      auto lut_indexes = message_and_carry_extract_luts->get_lut_indexes(0, 0);
      cuda_memcpy_async_to_gpu(lut_indexes, h_lut_indexes,
                               2 * num_lwes * sizeof(Torus), streams[0],
                               gpu_indexes[0]);

      message_and_carry_extract_bool_luts->set_lwe_indexes(
          streams[0], gpu_indexes[0], h_indexes_in, h_indexes_out);
      lut_indexes = message_and_carry_extract_bool_luts->get_lut_indexes(0, 0);
      cuda_memcpy_async_to_gpu(lut_indexes, h_lut_indexes,
                               2 * num_lwes * sizeof(Torus), streams[0],
                               gpu_indexes[0]);

      message_and_carry_extract_luts->broadcast_lut(streams, gpu_indexes, 0);
      message_and_carry_extract_bool_luts->broadcast_lut(streams, gpu_indexes,
                                                         0);

      tmp_expanded_lwes = (Torus *)cuda_malloc_async(
          num_lwes * (params.big_lwe_dimension + 1) * sizeof(Torus), streams[0],
          gpu_indexes[0]);

      cuda_synchronize_stream(streams[0], gpu_indexes[0]);
      free(h_indexes_in);
      free(h_indexes_out);
      free(h_lut_indexes);
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    message_and_carry_extract_luts->release(streams, gpu_indexes, gpu_count);
    delete message_and_carry_extract_luts;
    message_and_carry_extract_bool_luts->release(streams, gpu_indexes,
                                                 gpu_count);
    delete message_and_carry_extract_bool_luts;

    cuda_drop_async(tmp_expanded_lwes, streams[0], gpu_indexes[0]);
  }
};

#endif // ZK_UTILITIES_H

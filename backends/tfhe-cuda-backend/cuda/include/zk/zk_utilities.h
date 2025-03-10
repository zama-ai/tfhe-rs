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

  int_radix_lut<Torus> *message_and_carry_extract_many_luts;

  // Booleans have to be sanitized
  int_radix_lut<Torus> *message_and_carry_extract_bool_many_lut;

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
        return x / params.carry_modulus;
      };
    std::vector<std::function<Torus(Torus)>> message_and_carry_extract_many_luts_f = {
        message_extract_lut_f, carry_extract_lut_f};

      auto sanitize_bool_f = [params](Torus x) -> Torus {
        return (x == 0) ? 0 : 1;
      };
      auto message_extract_and_sanitize_bool_lut_f =
          [params, sanitize_bool_f](Torus x) -> Torus {
        return sanitize_bool_f(x % params.message_modulus);
      };
      auto carry_extract_and_sanitize_bool_lut_f =
          [params, sanitize_bool_f](Torus x) -> Torus {
        return sanitize_bool_f(x / params.message_modulus);
      };
    std::vector<std::function<Torus(Torus)>> message_and_carry_extract_bool_many_lut_f = {
        message_extract_and_sanitize_bool_lut_f, carry_extract_and_sanitize_bool_lut_f};


      message_and_carry_extract_many_luts =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                   num_lwes, 2, allocate_gpu_memory);

      message_and_carry_extract_bool_many_lut =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 1,
                                   num_lwes, 2, allocate_gpu_memory);

      generate_many_lut_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], message_and_carry_extract_many_luts->get_lut(0,0),
          message_and_carry_extract_many_luts->get_degree(0),
          message_and_carry_extract_many_luts->get_max_degree(0), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          message_and_carry_extract_many_luts_f);

      generate_many_lut_device_accumulator<Torus>(
          streams[0], gpu_indexes[0], message_and_carry_extract_bool_many_lut->get_lut(0,0),
          message_and_carry_extract_bool_many_lut->get_degree(0),
          message_and_carry_extract_bool_many_lut->get_max_degree(0), params.glwe_dimension,
          params.polynomial_size, params.message_modulus, params.carry_modulus,
          message_and_carry_extract_bool_many_lut_f);

      message_and_carry_extract_many_luts->broadcast_lut(streams, gpu_indexes, 0);
      message_and_carry_extract_bool_many_lut->broadcast_lut(streams, gpu_indexes, 0);

      tmp_expanded_lwes = (Torus *)cuda_malloc_async(
          num_lwes * (params.big_lwe_dimension + 1) * sizeof(Torus), streams[0],
          gpu_indexes[0]);
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    message_and_carry_extract_many_luts->release(streams, gpu_indexes, gpu_count);
    message_and_carry_extract_bool_many_lut->release(streams, gpu_indexes, gpu_count);
    cuda_drop_async(tmp_expanded_lwes, streams[0], gpu_indexes[0]);
  }
};

#endif // ZK_UTILITIES_H

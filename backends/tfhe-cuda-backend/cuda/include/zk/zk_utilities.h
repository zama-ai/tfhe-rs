#ifndef ZK_UTILITIES_H
#define ZK_UTILITIES_H

#include "../integer/integer_utilities.h"
#include "integer/integer.cuh"
#include <cstdint>

template <typename Torus> struct zk_expand_mem {
  int_radix_params computing_params;
  int_radix_params casting_params;
  bool casting_key_type;
  uint32_t num_lwes;
  uint32_t num_compact_lists;

  int_radix_lut<Torus> *message_and_carry_extract_luts;

  Torus *tmp_expanded_lwes;
  Torus *tmp_ksed_small_to_big_expanded_lwes;

  uint32_t *h_compact_list_length_per_lwe;
  uint32_t *d_compact_list_length_per_lwe;

  uint32_t *d_lwe_compact_input_indexes;

  zk_expand_mem(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                uint32_t gpu_count, int_radix_params computing_params,
                int_radix_params casting_params, KS_TYPE casting_key_type,
                const uint32_t *num_lwes_per_compact_list,
                const bool *is_boolean_array, uint32_t num_compact_lists,
                bool allocate_gpu_memory)
      : computing_params(computing_params), casting_params(casting_params),
        num_compact_lists(num_compact_lists),
        casting_key_type(casting_key_type) {

    num_lwes = 0;
    for (int i = 0; i < num_compact_lists; i++) {
      num_lwes += num_lwes_per_compact_list[i];
    }

    if (computing_params.carry_modulus != computing_params.message_modulus) {
      PANIC("GPU backend requires carry_modulus equal to message_modulus")
    }

    if (allocate_gpu_memory) {

      h_compact_list_length_per_lwe =
          (uint32_t *)malloc(num_lwes * sizeof(uint32_t));
      d_compact_list_length_per_lwe = (uint32_t *)cuda_malloc_async(
          num_lwes * sizeof(uint32_t), streams[0], gpu_indexes[0]);

      // This loop iterates over the total number of input LWEs and assigns
      // the compact list size related to each LWE based on the provided
      // array `num_lwes_per_compact_list`. The indices and count values are
      // used to track which compact list each LWE belongs to. Essentially, it
      // prepares the `h_compact_list_size_per_thread` array by mapping each LWE
      // index to the corresponding compact list size, ensuring each LWE has the
      // correct size configuration.
      auto idx = 0;
      auto count = 0;
      for (int i = 0; i < num_lwes; i++) {
        if (count == num_lwes_per_compact_list[idx]) {
          idx++;
          count = 0;
        }
        h_compact_list_length_per_lwe[i] = num_lwes_per_compact_list[idx];
        count++;
      }

      cuda_memcpy_async_to_gpu(
          d_compact_list_length_per_lwe, h_compact_list_length_per_lwe,
          num_lwes * sizeof(uint32_t), streams[0], gpu_indexes[0]);

      d_lwe_compact_input_indexes = static_cast<uint32_t *>(cuda_malloc_async(
          num_lwes * sizeof(uint32_t), streams[0], gpu_indexes[0]));
      auto h_lwe_compact_input_indexes =
          (uint32_t *)malloc(num_lwes * sizeof(uint32_t));

      auto compact_list_id = 0;
      idx = 0;
      count = 0;
      for (int i = 0; i < num_lwes; i++) {
        h_lwe_compact_input_indexes[i] = idx;
        count++;
        if (count == num_lwes_per_compact_list[compact_list_id]) {
          compact_list_id++;
          idx += casting_params.big_lwe_dimension + count;
          count = 0;
        }
      }

      cuda_memcpy_async_to_gpu(
          d_lwe_compact_input_indexes, h_lwe_compact_input_indexes,
          num_lwes * sizeof(uint32_t), streams[0], gpu_indexes[0]);

      auto message_extract_lut_f = [casting_params](Torus x) -> Torus {
        return x % casting_params.message_modulus;
      };
      auto carry_extract_lut_f = [casting_params](Torus x) -> Torus {
        return (x / casting_params.carry_modulus) %
               casting_params.message_modulus;
      };

      // Booleans have to be sanitized
      auto sanitize_bool_f = [](Torus x) -> Torus { return x == 0 ? 0 : 1; };
      auto message_extract_and_sanitize_bool_lut_f =
          [message_extract_lut_f, sanitize_bool_f](Torus x) -> Torus {
        return sanitize_bool_f(message_extract_lut_f(x));
      };
      auto carry_extract_and_sanitize_bool_lut_f =
          [carry_extract_lut_f, sanitize_bool_f](Torus x) -> Torus {
        return sanitize_bool_f(carry_extract_lut_f(x));
      };

      /** In case the casting key casts from BIG to SMALL key we run a single KS
      to expand using the casting key as ksk. Otherwise, in case the casting key
      casts from SMALL to BIG key, we first keyswitch from SMALL to BIG using
      the casting key as ksk, then we keyswitch from BIG to SMALL using the
      computing ksk, and lastly we apply the PBS. The output is always on the
      BIG key.
      **/
      auto params = casting_params;
      if (casting_key_type == SMALL_TO_BIG) {
        params = computing_params;
      }
      message_and_carry_extract_luts =
          new int_radix_lut<Torus>(streams, gpu_indexes, gpu_count, params, 4,
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
          message_and_carry_extract_luts->get_lut(0, 2),
          message_and_carry_extract_luts->get_degree(2),
          message_and_carry_extract_luts->get_max_degree(2),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, message_extract_and_sanitize_bool_lut_f);

      generate_device_accumulator<Torus>(
          streams[0], gpu_indexes[0],
          message_and_carry_extract_luts->get_lut(0, 3),
          message_and_carry_extract_luts->get_degree(3),
          message_and_carry_extract_luts->get_max_degree(3),
          params.glwe_dimension, params.polynomial_size, params.message_modulus,
          params.carry_modulus, carry_extract_and_sanitize_bool_lut_f);

      // Hint for future readers: if message_modulus == 4 then
      // packed_messages_per_lwe becomes 2
      auto packed_messages_per_lwe = log2_int(params.message_modulus);

      // Adjust indexes to permute the output and access the correct LUT
      auto h_indexes_in = static_cast<Torus *>(
          malloc(packed_messages_per_lwe * num_lwes * sizeof(Torus)));
      auto h_indexes_out = static_cast<Torus *>(
          malloc(packed_messages_per_lwe * num_lwes * sizeof(Torus)));
      auto h_lut_indexes = static_cast<Torus *>(
          malloc(packed_messages_per_lwe * num_lwes * sizeof(Torus)));

      auto offset = 0;
      for (int k = 0; k < num_compact_lists; k++) {
        auto num_lwes_in_kth_compact_list = num_lwes_per_compact_list[k];
        for (int i = 0;
             i < packed_messages_per_lwe * num_lwes_in_kth_compact_list; i++) {
          Torus j = i % num_lwes_in_kth_compact_list;
          h_indexes_in[i + packed_messages_per_lwe * offset] = j + offset;
          h_indexes_out[i + packed_messages_per_lwe * offset] =
              packed_messages_per_lwe * (j + offset) +
              (i / num_lwes_in_kth_compact_list);
          // If the input relates to a boolean, shift the LUT so the correct one
          // with sanitization is used
          h_lut_indexes[i + packed_messages_per_lwe * offset] =
              (is_boolean_array[h_indexes_out[i +
                                              packed_messages_per_lwe * offset]]
                   ? packed_messages_per_lwe
                   : 0) +
              i / num_lwes_in_kth_compact_list;
        }
        offset += num_lwes_in_kth_compact_list;
      }

      message_and_carry_extract_luts->set_lwe_indexes(
          streams[0], gpu_indexes[0], h_indexes_in, h_indexes_out);
      auto lut_indexes = message_and_carry_extract_luts->get_lut_indexes(0, 0);
      cuda_memcpy_async_to_gpu(lut_indexes, h_lut_indexes,
                               packed_messages_per_lwe * num_lwes *
                                   sizeof(Torus),
                               streams[0], gpu_indexes[0]);

      message_and_carry_extract_luts->broadcast_lut(streams, gpu_indexes, 0);

      // The expanded LWEs will always be on the casting key format
      tmp_expanded_lwes = (Torus *)cuda_malloc_async(
          num_lwes * (casting_params.big_lwe_dimension + 1) * sizeof(Torus),
          streams[0], gpu_indexes[0]);

      tmp_ksed_small_to_big_expanded_lwes = (Torus *)cuda_malloc_async(
          num_lwes * (casting_params.big_lwe_dimension + 1) * sizeof(Torus),
          streams[0], gpu_indexes[0]);

      cuda_synchronize_stream(streams[0], gpu_indexes[0]);
      free(h_indexes_in);
      free(h_indexes_out);
      free(h_lut_indexes);
      free(h_lwe_compact_input_indexes);
    }
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    message_and_carry_extract_luts->release(streams, gpu_indexes, gpu_count);
    delete message_and_carry_extract_luts;

    cuda_drop_async(tmp_expanded_lwes, streams[0], gpu_indexes[0]);
    cuda_drop_async(d_compact_list_length_per_lwe, streams[0], gpu_indexes[0]);
    free(h_compact_list_length_per_lwe);
  }
};

#endif // ZK_UTILITIES_H

#ifndef ZK_UTILITIES_H
#define ZK_UTILITIES_H

#include "../integer/integer_utilities.h"
#include "integer/integer.cuh"
#include <cstdint>

template <typename Torus> struct lwe_mask {
  Torus *mask;
  uint32_t lwe_dimension;

  lwe_mask(Torus *mask, uint32_t lwe_dimension)
      : mask{mask}, lwe_dimension{lwe_dimension} {}
};

template <typename Torus> struct compact_lwe_body {
  Torus *body;
  uint64_t monomial_degree;

  compact_lwe_body(Torus *body, uint64_t monomial_degree)
      : body{body}, monomial_degree{monomial_degree} {}
};

template <typename Torus> struct compact_lwe_list {
  Torus *list_start;
  uint32_t lwe_dimension;
  uint32_t total_num_lwes;

  compact_lwe_list(Torus *list_start, uint32_t lwe_dimension,
                   uint32_t total_num_lwes)
      : list_start{list_start}, lwe_dimension{lwe_dimension},
        total_num_lwes{total_num_lwes} {}

  lwe_mask<Torus> get_mask() { return lwe_mask(list_start, lwe_dimension); }

  compact_lwe_body<Torus> get_body(uint32_t index) {
    if (index >= total_num_lwes) {
      PANIC("index out of range in compact_lwe_list::get_body");
    }

    return compact_lwe_body(&list_start[lwe_dimension + index], uint64_t(index));
  }
};

template <typename Torus> struct flattened_compact_lwe_lists {
  Torus *list_start;
  const uint32_t *num_lwes_per_compact_list;
  uint32_t num_compact_lists;
  uint32_t lwe_dimension;
  uint32_t total_num_lwes;

  flattened_compact_lwe_lists(Torus *list_start,
                              const uint32_t *num_lwes_per_compact_list,
                              uint32_t num_compact_lists,
                              uint32_t lwe_dimension)
      : list_start{list_start},
        num_lwes_per_compact_list{num_lwes_per_compact_list},
        num_compact_lists{num_compact_lists}, lwe_dimension{lwe_dimension} {
    total_num_lwes = 0;
    for (uint32_t i = 0; i < num_compact_lists; ++i) {
      total_num_lwes += num_lwes_per_compact_list[i];
    }
  }

  compact_lwe_list<Torus> get(uint32_t index) {
    if (index >= num_compact_lists) {
      PANIC("index out of range in flattened_compact_lwe_lists::get");
    }

    Torus *curr_list_start = list_start;

    uint32_t curr_index;

    // TODO: This is super suboptimal, in practice should cache where each list
    // begins in the constructor and cache the value internally
    for (curr_index = 0; curr_index == index; ++curr_index) {
      // lwe_dimension for the size of the mask + the number of bodies of the
      // current list to get the start of the next list
      curr_list_start = &curr_list_start[lwe_dimension +
                                         num_lwes_per_compact_list[curr_index]];
    }

    return compact_lwe_list(curr_list_start, lwe_dimension,
                            num_lwes_per_compact_list[curr_index]);
  }
};

template <typename Torus> struct expand_job {
  lwe_mask<Torus> mask_to_use;
  compact_lwe_body<Torus> body_to_use;

  expand_job(lwe_mask<Torus> mask_to_use, compact_lwe_body<Torus> body_to_use)
      : mask_to_use{mask_to_use}, body_to_use{body_to_use} {}
};

template <typename Torus> struct zk_expand_mem {
  int_radix_params computing_params;
  int_radix_params casting_params;
  bool casting_key_type;
  uint32_t num_lwes;
  uint32_t num_compact_lists;

  int_radix_lut<Torus> *message_and_carry_extract_luts;

  Torus *tmp_expanded_lwes;
  Torus *tmp_ksed_small_to_big_expanded_lwes;

  uint32_t *d_lwe_compact_input_indexes;

  uint32_t *d_body_id_per_compact_list;
  bool gpu_memory_allocated;
  expand_job<Torus> *d_expand_jobs;

  zk_expand_mem(cudaStream_t const *streams, uint32_t const *gpu_indexes,
                uint32_t gpu_count, int_radix_params computing_params,
                int_radix_params casting_params, KS_TYPE casting_key_type,
                Torus *flattened_lwe_compact_lists,
                const uint32_t flattened_lwe_compact_list_lwe_dimension,
                const uint32_t *num_lwes_per_compact_list,
                const bool *is_boolean_array, uint32_t num_compact_lists,
                bool allocate_gpu_memory, uint64_t &size_tracker)
      : computing_params(computing_params), casting_params(casting_params),
        num_compact_lists(num_compact_lists),
        casting_key_type(casting_key_type) {

    gpu_memory_allocated = allocate_gpu_memory;
    auto compact_lwe_lists = flattened_compact_lwe_lists(
        flattened_lwe_compact_lists, num_lwes_per_compact_list,
        num_compact_lists, flattened_lwe_compact_list_lwe_dimension);

    num_lwes = compact_lwe_lists.total_num_lwes;

    if (computing_params.carry_modulus != computing_params.message_modulus) {
      PANIC("GPU backend requires carry_modulus equal to message_modulus")
    }

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
    message_and_carry_extract_luts = new int_radix_lut<Torus>(
        streams, gpu_indexes, gpu_count, params, 4, 2 * num_lwes,
        allocate_gpu_memory, size_tracker);

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0],
        message_and_carry_extract_luts->get_lut(0, 0),
        message_and_carry_extract_luts->get_degree(0),
        message_and_carry_extract_luts->get_max_degree(0),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, message_extract_lut_f, gpu_memory_allocated);

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0],
        message_and_carry_extract_luts->get_lut(0, 1),
        message_and_carry_extract_luts->get_degree(1),
        message_and_carry_extract_luts->get_max_degree(1),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, carry_extract_lut_f, gpu_memory_allocated);

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0],
        message_and_carry_extract_luts->get_lut(0, 2),
        message_and_carry_extract_luts->get_degree(2),
        message_and_carry_extract_luts->get_max_degree(2),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, message_extract_and_sanitize_bool_lut_f,
        gpu_memory_allocated);

    generate_device_accumulator<Torus>(
        streams[0], gpu_indexes[0],
        message_and_carry_extract_luts->get_lut(0, 3),
        message_and_carry_extract_luts->get_degree(3),
        message_and_carry_extract_luts->get_max_degree(3),
        params.glwe_dimension, params.polynomial_size, params.message_modulus,
        params.carry_modulus, carry_extract_and_sanitize_bool_lut_f,
        gpu_memory_allocated);

    // Hint for future readers: if message_modulus == 4 then
    // packed_messages_per_lwe becomes 2
    auto num_packed_msgs = log2_int(params.message_modulus);

    // Adjust indexes to permute the output and access the correct LUT
    auto h_indexes_in = static_cast<Torus *>(
        malloc(num_packed_msgs * num_lwes * sizeof(Torus)));
    auto h_indexes_out = static_cast<Torus *>(
        malloc(num_packed_msgs * num_lwes * sizeof(Torus)));
    auto h_lut_indexes = static_cast<Torus *>(
        malloc(num_packed_msgs * num_lwes * sizeof(Torus)));
    auto h_body_id_per_compact_list =
        static_cast<uint32_t *>(malloc(num_lwes * sizeof(uint32_t)));
    auto h_lwe_compact_input_indexes =
        static_cast<uint32_t *>(malloc(num_lwes * sizeof(uint32_t)));

    d_body_id_per_compact_list =
        static_cast<uint32_t *>(cuda_malloc_with_size_tracking_async(
            num_lwes * sizeof(uint32_t), streams[0], gpu_indexes[0],
            size_tracker, allocate_gpu_memory));
    d_lwe_compact_input_indexes =
        static_cast<uint32_t *>(cuda_malloc_with_size_tracking_async(
            num_lwes * sizeof(uint32_t), streams[0], gpu_indexes[0],
            size_tracker, allocate_gpu_memory));

    auto compact_list_id = 0;
    auto idx = 0;
    auto count = 0;
    // During flattening, all num_lwes LWEs from all compact lists are stored
    // sequentially on a Torus array. h_lwe_compact_input_indexes stores the
    // index of the first LWE related to the compact list that contains the i-th
    // LWE
    for (int i = 0; i < num_lwes; i++) {
      h_lwe_compact_input_indexes[i] = idx;
      count++;
      if (count == num_lwes_per_compact_list[compact_list_id]) {
        compact_list_id++;
        idx += casting_params.big_lwe_dimension + count;
        count = 0;
      }
    }

    // Stores the index of the i-th LWE (within each compact list) related to
    // the k-th compact list.
    auto offset = 0;
    for (int k = 0; k < num_compact_lists; k++) {
      auto num_lwes_in_kth_compact_list = num_lwes_per_compact_list[k];
      uint32_t body_count = 0;
      for (int i = 0; i < num_lwes_in_kth_compact_list; i++) {
        h_body_id_per_compact_list[i + offset] = body_count;
        body_count++;
      }
      offset += num_lwes_in_kth_compact_list;
    }

    d_expand_jobs =
        static_cast<expand_job<Torus> *>(cuda_malloc_with_size_tracking_async(
            num_lwes * sizeof(expand_job<Torus>), streams[0], gpu_indexes[0],
            size_tracker, allocate_gpu_memory));

    std::vector<expand_job<Torus>> h_expand_jobs;
    h_expand_jobs.reserve(num_lwes);

    for (auto list_index = 0; list_index < compact_lwe_lists.num_compact_lists;
         ++list_index) {
      auto list = compact_lwe_lists.get(list_index);
      for (auto lwe_index = 0; lwe_index < list.total_num_lwes; ++lwe_index) {
        auto job = expand_job<Torus>(list.get_mask(), list.get_body(lwe_index));
        h_expand_jobs.push_back(job);
      }
    }

    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_expand_jobs, h_expand_jobs.data(),
        h_expand_jobs.size() * sizeof(expand_job<Torus>), streams[0],
        gpu_indexes[0], allocate_gpu_memory);

    /*
     * Each LWE contains encrypted data in both carry and message spaces
     * that needs to be extracted.
     *
     * The loop processes each compact list (k) and for each LWE within that
     * list:
     * 1. Sets input indexes to read each LWE twice (for carry and message
     * extraction)
     * 2. Creates output indexes to properly reorder the results
     * 3. Selects appropriate LUT index based on whether boolean sanitization is
     * needed
     *
     * We want the output to have always first the content of the message part
     * and then the content of the carry part of each LWE.
     *
     * i.e. msg_extract(LWE_0), carry_extract(LWE_0), msg_extract(LWE_1),
     * carry_extract(LWE_1), ...
     *
     * Aiming that behavior, with 4 LWEs we would have:
     *
     * // Each LWE is processed twice
     * h_indexes_in   = {0, 1, 2, 3, 0, 1, 2, 3}
     *
     * // First 4 use message LUT, last 4 use carry LUT
     * h_lut_indexes  = {0, 0, 0, 0, 1, 1, 1, 1}
     *
     * // Reorders output so message and carry for each LWE appear together
     * h_indexes_out  = {0, 2, 4, 6, 1, 3, 5, 7}
     *
     * If an LWE contains a boolean value, its LUT index is shifted by
     * num_packed_msgs to use the sanitization LUT (which ensures output is
     * exactly 0 or 1).
     */
    offset = 0;
    for (int k = 0; k < num_compact_lists; k++) {
      auto num_lwes_in_kth = num_lwes_per_compact_list[k];
      for (int i = 0; i < num_packed_msgs * num_lwes_in_kth; i++) {
        auto lwe_index = i + num_packed_msgs * offset;
        auto lwe_index_in_list = i % num_lwes_in_kth;
        h_indexes_in[lwe_index] = lwe_index_in_list + offset;
        h_indexes_out[lwe_index] =
            num_packed_msgs * h_indexes_in[lwe_index] + i / num_lwes_in_kth;
        // If the input relates to a boolean, shift the LUT so the correct one
        // with sanitization is used
        auto boolean_offset =
            is_boolean_array[h_indexes_out[lwe_index]] ? num_packed_msgs : 0;
        h_lut_indexes[lwe_index] = i / num_lwes_in_kth + boolean_offset;
      }
      offset += num_lwes_in_kth;
    }

    message_and_carry_extract_luts->set_lwe_indexes(
        streams[0], gpu_indexes[0], h_indexes_in, h_indexes_out);
    auto lut_indexes = message_and_carry_extract_luts->get_lut_indexes(0, 0);

    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_lwe_compact_input_indexes, h_lwe_compact_input_indexes,
        num_lwes * sizeof(uint32_t), streams[0], gpu_indexes[0],
        allocate_gpu_memory);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        lut_indexes, h_lut_indexes, num_packed_msgs * num_lwes * sizeof(Torus),
        streams[0], gpu_indexes[0], allocate_gpu_memory);
    cuda_memcpy_with_size_tracking_async_to_gpu(
        d_body_id_per_compact_list, h_body_id_per_compact_list,
        num_lwes * sizeof(uint32_t), streams[0], gpu_indexes[0],
        allocate_gpu_memory);

    message_and_carry_extract_luts->broadcast_lut(streams, gpu_indexes);

    // The expanded LWEs will always be on the casting key format
    tmp_expanded_lwes = (Torus *)cuda_malloc_with_size_tracking_async(
        num_lwes * (casting_params.big_lwe_dimension + 1) * sizeof(Torus),
        streams[0], gpu_indexes[0], size_tracker, allocate_gpu_memory);

    tmp_ksed_small_to_big_expanded_lwes =
        (Torus *)cuda_malloc_with_size_tracking_async(
            num_lwes * (casting_params.big_lwe_dimension + 1) * sizeof(Torus),
            streams[0], gpu_indexes[0], size_tracker, allocate_gpu_memory);

    cuda_synchronize_stream(streams[0], gpu_indexes[0]);
    free(h_indexes_in);
    free(h_indexes_out);
    free(h_lut_indexes);
    free(h_body_id_per_compact_list);
    free(h_lwe_compact_input_indexes);
  }

  void release(cudaStream_t const *streams, uint32_t const *gpu_indexes,
               uint32_t gpu_count) {

    message_and_carry_extract_luts->release(streams, gpu_indexes, gpu_count);
    delete message_and_carry_extract_luts;

    cuda_drop_with_size_tracking_async(d_body_id_per_compact_list, streams[0],
                                       gpu_indexes[0], gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_lwe_compact_input_indexes, streams[0],
                                       gpu_indexes[0], gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(tmp_expanded_lwes, streams[0],
                                       gpu_indexes[0], gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(tmp_ksed_small_to_big_expanded_lwes,
                                       streams[0], gpu_indexes[0],
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_expand_jobs, streams[0],
                                       gpu_indexes[0], gpu_memory_allocated);
  }
};

#endif // ZK_UTILITIES_H

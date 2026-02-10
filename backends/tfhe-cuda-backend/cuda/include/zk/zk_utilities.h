#ifndef ZK_UTILITIES_H
#define ZK_UTILITIES_H

#include "../integer/integer_utilities.h"
#include "integer/integer.cuh"
#include <cstdint>

////////////////////////////////////
// Helper structures used in expand
template <typename Torus> struct lwe_mask {
  Torus *mask;

  lwe_mask(Torus *mask) : mask{mask} {}
};

template <typename Torus> struct compact_lwe_body {
  Torus *body;
  uint64_t monomial_degree;

  /* Body id is the index of the body in the compact ciphertext list.
   *  It's used to compute the rotation.
   */
  compact_lwe_body(Torus *body, const uint64_t body_id)
      : body{body}, monomial_degree{body_id} {}
};

template <typename Torus> struct compact_lwe_list {
  Torus *ptr;
  uint32_t lwe_dimension;
  uint32_t total_num_lwes;

  compact_lwe_list(Torus *ptr, uint32_t lwe_dimension, uint32_t total_num_lwes)
      : ptr{ptr}, lwe_dimension{lwe_dimension}, total_num_lwes{total_num_lwes} {
  }

  lwe_mask<Torus> get_mask() { return lwe_mask(ptr); }

  // Returns the index-th body
  compact_lwe_body<Torus> get_body(uint32_t index) {
    if (index >= total_num_lwes) {
      PANIC("index out of range in compact_lwe_list::get_body");
    }

    return compact_lwe_body(&ptr[lwe_dimension + index], uint64_t(index));
  }
};

template <typename Torus> struct flattened_compact_lwe_lists {
  Torus *d_ptr;
  Torus **ptr_array_to_d_compact_list;
  const uint32_t *h_num_lwes_per_compact_list;
  uint32_t num_compact_lists;
  uint32_t lwe_dimension;
  uint32_t total_num_lwes;

  flattened_compact_lwe_lists(Torus *d_ptr,
                              const uint32_t *h_num_lwes_per_compact_list,
                              uint32_t num_compact_lists,
                              uint32_t lwe_dimension)
      : d_ptr(d_ptr), h_num_lwes_per_compact_list(h_num_lwes_per_compact_list),
        num_compact_lists(num_compact_lists), lwe_dimension(lwe_dimension) {
    ptr_array_to_d_compact_list =
        static_cast<Torus **>(malloc(num_compact_lists * sizeof(Torus *)));
    total_num_lwes = 0;
    auto curr_list = d_ptr;
    for (auto i = 0; i < num_compact_lists; ++i) {
      total_num_lwes += h_num_lwes_per_compact_list[i];
      ptr_array_to_d_compact_list[i] = curr_list;
      curr_list += lwe_dimension + h_num_lwes_per_compact_list[i];
    }
  }

  compact_lwe_list<Torus> get_device_compact_list(uint32_t compact_list_index) {
    if (compact_list_index >= num_compact_lists) {
      PANIC("index out of range in flattened_compact_lwe_lists::get");
    }

    return compact_lwe_list(ptr_array_to_d_compact_list[compact_list_index],
                            lwe_dimension,
                            h_num_lwes_per_compact_list[compact_list_index]);
  }

  void release() { free(ptr_array_to_d_compact_list); }
};

/*
 * A expand_job tells the expand kernel exactly which input mask and body to use
 * and what rotation to apply
 */
template <typename Torus> struct expand_job {
  lwe_mask<Torus> mask_to_use;
  compact_lwe_body<Torus> body_to_use;

  expand_job(lwe_mask<Torus> mask_to_use, compact_lwe_body<Torus> body_to_use)
      : mask_to_use{mask_to_use}, body_to_use{body_to_use} {}
};

////////////////////////////////////

template <typename Torus> struct zk_expand_mem {
  int_radix_params computing_params;
  int_radix_params casting_params;
  bool casting_key_type;
  uint32_t num_lwes;
  uint32_t num_compact_lists;

  int_radix_lut<Torus> *message_and_carry_extract_luts;

  Torus *tmp_expanded_lwes;
  Torus *tmp_ksed_small_to_big_expanded_lwes;

  bool gpu_memory_allocated;

  uint32_t *num_lwes_per_compact_list;
  expand_job<Torus> *d_expand_jobs;
  expand_job<Torus> *h_expand_jobs;

  zk_expand_mem(CudaStreams streams, int_radix_params computing_params,
                int_radix_params casting_params, KS_TYPE casting_key_type,
                const uint32_t *num_lwes_per_compact_list,
                const bool *is_boolean_array,
                const uint32_t is_boolean_array_len, uint32_t num_compact_lists,
                bool allocate_gpu_memory, uint64_t &size_tracker)
      : computing_params(computing_params), casting_params(casting_params),
        num_compact_lists(num_compact_lists),
        casting_key_type(casting_key_type) {
    gpu_memory_allocated = allocate_gpu_memory;

    // We copy num_lwes_per_compact_list so we get protection against
    // num_lwes_per_compact_list being freed while this buffer is still in use
    this->num_lwes_per_compact_list =
        (uint32_t *)malloc(num_compact_lists * sizeof(uint32_t));
    memcpy(this->num_lwes_per_compact_list, num_lwes_per_compact_list,
           num_compact_lists * sizeof(uint32_t));

    num_lwes = 0;
    for (int i = 0; i < num_compact_lists; i++) {
      num_lwes += this->num_lwes_per_compact_list[i];
    }

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
        streams, params, 4, 2 * num_lwes, allocate_gpu_memory, size_tracker);

    // We are always packing two LWEs. We just need to be sure we have enough
    // space in the carry part to store a message of the same size as is in the
    // message part.
    if (params.carry_modulus < params.message_modulus)
      PANIC("Carry modulus must be at least as large as message modulus");
    auto num_packed_msgs = 2;

    // Adjust indexes to permute the output and access the correct LUT
    auto h_indexes_in = static_cast<Torus *>(
        malloc(num_packed_msgs * num_lwes * sizeof(Torus)));
    auto h_indexes_out = static_cast<Torus *>(
        malloc(num_packed_msgs * num_lwes * sizeof(Torus)));
    HostBuffer<Torus> h_lut_indexes;
    h_lut_indexes.allocate(num_packed_msgs * num_lwes);

    d_expand_jobs =
        static_cast<expand_job<Torus> *>(cuda_malloc_with_size_tracking_async(
            num_lwes * sizeof(expand_job<Torus>), streams.stream(0),
            streams.gpu_index(0), size_tracker, allocate_gpu_memory));

    h_expand_jobs = static_cast<expand_job<Torus> *>(
        malloc(num_lwes * sizeof(expand_job<Torus>)));

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
    auto offset = 0;
    for (int k = 0; k < num_compact_lists; k++) {
      auto num_lwes_in_kth = this->num_lwes_per_compact_list[k];
      for (int i = 0; i < num_packed_msgs * num_lwes_in_kth; i++) {
        auto lwe_index = i + num_packed_msgs * offset;
        auto lwe_index_in_list = i % num_lwes_in_kth;
        PANIC_IF_FALSE(lwe_index < num_packed_msgs * num_lwes,
                       "Cuda error: index %d is beyond the max value %d",
                       lwe_index, num_packed_msgs * num_lwes);
        h_indexes_in[lwe_index] = lwe_index_in_list + offset;
        h_indexes_out[lwe_index] =
            num_packed_msgs * h_indexes_in[lwe_index] + i / num_lwes_in_kth;
        PANIC_IF_FALSE(h_indexes_in[lwe_index] < num_packed_msgs * num_lwes,
                       "Cuda error: index %d is beyond the max value %d",
                       h_indexes_in[lwe_index], num_packed_msgs * num_lwes);
        PANIC_IF_FALSE(h_indexes_out[lwe_index] < num_packed_msgs * num_lwes,
                       "Cuda error: index %d is beyond the max value %d",
                       h_indexes_out[lwe_index], num_packed_msgs * num_lwes);
        // is_boolean_array tells us which input is a boolean and thus the
        // related output needs boolean sanitization. It naturally has
        // total_blocks entries, but h_indexes_out reaches
        // message_modulus * ceil(total_blocks/2) - 1. When total_blocks is odd,
        // the ceiling causes out-of-bounds access. Reading garbage "true" would
        // set h_lut_indexes to an invalid index pointing to uninitialized
        // memory instead of a real LUT. Rust pads is_boolean_array with FALSE
        // to match.
        PANIC_IF_FALSE(h_indexes_out[lwe_index] < is_boolean_array_len,
                       "Cuda error: index %d for is_boolean_array is out of "
                       "bounds (len is %d)",
                       h_indexes_out[lwe_index], is_boolean_array_len);
      }
      offset += num_lwes_in_kth;
    }

    message_and_carry_extract_luts->set_lwe_indexes(
        streams.stream(0), streams.gpu_index(0), h_indexes_in, h_indexes_out);

    auto active_streams =
        streams.active_gpu_subset(2 * num_lwes, params.pbs_type);

    // Index generator for message/carry extraction LUTs
    auto index_gen = [num_compact_lists,
                      num_lwes_per_compact_list =
                          this->num_lwes_per_compact_list,
                      num_packed_msgs, is_boolean_array, h_indexes_out](
                         HostBuffer<Torus> &h_lut_indexes, uint32_t) {
      auto offset = 0;
      for (int k = 0; k < num_compact_lists; k++) {
        auto num_lwes_in_kth = num_lwes_per_compact_list[k];
        for (int i = 0; i < num_packed_msgs * num_lwes_in_kth; i++) {
          auto lwe_index = i + num_packed_msgs * offset;
          auto boolean_offset =
              is_boolean_array[h_indexes_out[lwe_index]] ? num_packed_msgs : 0;
          h_lut_indexes[lwe_index] = i / num_lwes_in_kth + boolean_offset;
        }
        offset += num_lwes_in_kth;
      }
    };

    message_and_carry_extract_luts->generate_and_broadcast_lut(
        active_streams, {0, 1, 2, 3},
        {message_extract_lut_f, carry_extract_lut_f,
         message_extract_and_sanitize_bool_lut_f,
         carry_extract_and_sanitize_bool_lut_f},
        index_gen, true, {}, &h_lut_indexes);

    message_and_carry_extract_luts->allocate_lwe_vector_for_non_trivial_indexes(
        active_streams, 2 * num_lwes, size_tracker, allocate_gpu_memory);
    // The expanded LWEs will always be on the casting key format
    tmp_expanded_lwes = (Torus *)cuda_malloc_with_size_tracking_async(
        num_lwes * (casting_params.big_lwe_dimension + 1) * sizeof(Torus),
        streams.stream(0), streams.gpu_index(0), size_tracker,
        allocate_gpu_memory);

    tmp_ksed_small_to_big_expanded_lwes =
        (Torus *)cuda_malloc_with_size_tracking_async(
            num_lwes * (casting_params.big_lwe_dimension + 1) * sizeof(Torus),
            streams.stream(0), streams.gpu_index(0), size_tracker,
            allocate_gpu_memory);

    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    free(h_indexes_in);
    free(h_indexes_out);
    {
      auto gpu_phase = GpuReleasePhase(streams);
      auto cpu_phase = std::move(gpu_phase).synchronize();
      h_lut_indexes.release(cpu_phase);
    }
  }

  void release(CudaStreams streams) {
    message_and_carry_extract_luts->release(streams);
    delete message_and_carry_extract_luts;

    cuda_drop_with_size_tracking_async(tmp_expanded_lwes, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(tmp_ksed_small_to_big_expanded_lwes,
                                       streams.stream(0), streams.gpu_index(0),
                                       gpu_memory_allocated);
    cuda_drop_with_size_tracking_async(d_expand_jobs, streams.stream(0),
                                       streams.gpu_index(0),
                                       gpu_memory_allocated);
    cuda_synchronize_stream(streams.stream(0), streams.gpu_index(0));
    free(num_lwes_per_compact_list);
    free(h_expand_jobs);
  }
};

#endif // ZK_UTILITIES_H

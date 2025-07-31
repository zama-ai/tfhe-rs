#include "expand.cuh"

void cuda_lwe_expand_64(void *const stream, uint32_t gpu_index,
                        void *lwe_array_out, const void *lwe_compact_array_in,
                        uint32_t lwe_dimension, uint32_t num_lwe,
                        const uint32_t *lwe_compact_input_indexes,
                        const uint32_t *output_body_id_per_compact_list) {

  switch (lwe_dimension) {
  case 256:
    host_lwe_expand<uint64_t, AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out),
        static_cast<const uint64_t *>(lwe_compact_array_in), num_lwe,
        lwe_compact_input_indexes, output_body_id_per_compact_list);
    break;
  case 512:
    host_lwe_expand<uint64_t, AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out),
        static_cast<const uint64_t *>(lwe_compact_array_in), num_lwe,
        lwe_compact_input_indexes, output_body_id_per_compact_list);
    break;
  case 1024:
    host_lwe_expand<uint64_t, AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out),
        static_cast<const uint64_t *>(lwe_compact_array_in), num_lwe,
        lwe_compact_input_indexes, output_body_id_per_compact_list);
    break;
  case 2048:
    host_lwe_expand<uint64_t, AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out),
        static_cast<const uint64_t *>(lwe_compact_array_in), num_lwe,
        lwe_compact_input_indexes, output_body_id_per_compact_list);
    break;
  case 4096:
    host_lwe_expand<uint64_t, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out),
        static_cast<const uint64_t *>(lwe_compact_array_in), num_lwe,
        lwe_compact_input_indexes, output_body_id_per_compact_list);
    break;
  case 8192:
    host_lwe_expand<uint64_t, AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out),
        static_cast<const uint64_t *>(lwe_compact_array_in), num_lwe,
        lwe_compact_input_indexes, output_body_id_per_compact_list);
    break;
  case 16384:
    host_lwe_expand<uint64_t, AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out),
        static_cast<const uint64_t *>(lwe_compact_array_in), num_lwe,
        lwe_compact_input_indexes, output_body_id_per_compact_list);
    break;
  default:
    PANIC("CUDA error: lwe_dimension not supported."
          "Supported n's are powers of two"
          " in the interval [256..16384].");
    break;
  }
}

void alternate_cuda_lwe_expand_64(void *const stream, uint32_t gpu_index,
                                  void *lwe_array_out,
                                  uint32_t lwe_dimension, uint32_t num_lwe,
                                  const expand_job<uint64_t> *jobs) {

  switch (lwe_dimension) {
  case 256:
    alternate_host_lwe_expand<uint64_t, AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out), num_lwe, jobs);
    break;
  case 512:
    alternate_host_lwe_expand<uint64_t, AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out), num_lwe, jobs);
    break;
  case 1024:
    alternate_host_lwe_expand<uint64_t, AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out), num_lwe, jobs);
    break;
  case 2048:
    alternate_host_lwe_expand<uint64_t, AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out), num_lwe, jobs);
    break;
  case 4096:
    alternate_host_lwe_expand<uint64_t, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out), num_lwe, jobs);
    break;
  case 8192:
    alternate_host_lwe_expand<uint64_t, AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out), num_lwe, jobs);
    break;
  case 16384:
    alternate_host_lwe_expand<uint64_t, AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out), num_lwe, jobs);
    break;
  default:
    PANIC("CUDA error: lwe_dimension not supported."
          "Supported n's are powers of two"
          " in the interval [256..16384].");
    break;
  }
}

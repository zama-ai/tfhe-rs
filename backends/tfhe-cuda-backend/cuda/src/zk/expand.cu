#include "expand.cuh"

void cuda_lwe_expand_64(void *const stream, uint32_t gpu_index,
                        void *lwe_array_out, expand_job<uint64_t> *d_jobs,
                        uint32_t num_lwes, uint32_t lwe_dimension) {

  switch (lwe_dimension) {
  case 256:
    host_lwe_expand<uint64_t, AmortizedDegree<256>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out), d_jobs, num_lwes);
    break;
  case 512:
    host_lwe_expand<uint64_t, AmortizedDegree<512>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out), d_jobs, num_lwes);
    break;
  case 1024:
    host_lwe_expand<uint64_t, AmortizedDegree<1024>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out), d_jobs, num_lwes);
    break;
  case 2048:
    host_lwe_expand<uint64_t, AmortizedDegree<2048>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out), d_jobs, num_lwes);
    break;
  case 4096:
    host_lwe_expand<uint64_t, AmortizedDegree<4096>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out), d_jobs, num_lwes);
    break;
  case 8192:
    host_lwe_expand<uint64_t, AmortizedDegree<8192>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out), d_jobs, num_lwes);
    break;
  case 16384:
    host_lwe_expand<uint64_t, AmortizedDegree<16384>>(
        static_cast<cudaStream_t>(stream), gpu_index,
        static_cast<uint64_t *>(lwe_array_out), d_jobs, num_lwes);
    break;
  default:
    PANIC("CUDA error: lwe_dimension not supported."
          "Supported n's are powers of two"
          " in the interval [256..16384].");
    break;
  }
}

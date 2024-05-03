#ifndef TFHE_CUDA_BACKEND_POLYNOMIAL_H
#define TFHE_CUDA_BACKEND_POLYNOMIAL_H

#include <mutex>
#include "device.h"
#include "polynomial.h"

template <typename T, typename ST>
void cuda_batch_convert_std_to_fft(cuda_stream_t *stream, double2 *dest,
                                   ST *src, uint32_t polynomial_size,
                                   uint32_t total_polynomials);

struct monomials_t {
    double2* d_monomials;
    uint32_t polynomial_size;
    uint32_t gpu_index;
    bool is_init = false;
    std::mutex init_mutex;
    std::mutex release_mutex;


    // Default constructor
    monomials_t() : d_monomials(nullptr), is_init(false) {}

    void init(uint32_t gpu_index, uint32_t polynomial_size){
        std::lock_guard<std::mutex> lock(init_mutex);
        if(is_init && this->polynomial_size != polynomial_size)
            this->release(gpu_index);
        if(!is_init){
          // Pre-calculates all possible monomials_t to be used during keybundle
          // calculation
          int64_t *h_monomials = (int64_t *)malloc(
              2 * polynomial_size * polynomial_size * sizeof(int64_t));
          memset(h_monomials, 0,
                 2 * polynomial_size * polynomial_size * sizeof(int64_t));

          int64_t *monomial = h_monomials;
          for (uint32_t monomial_degree = 0; monomial_degree < 2 * polynomial_size;
               monomial_degree++) {
            int full_cycles_count = monomial_degree / polynomial_size;
            int remainder_degrees = monomial_degree % polynomial_size;
            monomial[remainder_degrees] = (full_cycles_count % 2 ? -1 : 1);
            monomial += polynomial_size;
          }
            auto stream = cuda_create_stream(gpu_index);

          d_monomials = (double2 *)cuda_malloc_async(
              2 * polynomial_size * polynomial_size / 2 * sizeof(double2), stream);
          cuda_batch_convert_std_to_fft<uint64_t>(
              stream, d_monomials, h_monomials, polynomial_size, 2 * polynomial_size);
          cuda_stream_add_callback(stream, host_free_on_stream_callback,
                                   h_monomials);
          stream->synchronize();
          stream->release();
          is_init = true;
          this->polynomial_size = polynomial_size;
        }
    }

    void release(uint32_t gpu_index){
        std::lock_guard<std::mutex> lock(release_mutex);
        cuda_drop(d_monomials, gpu_index);
          is_init = false;
    }
};
#endif // TFHE_CUDA_BACKEND_POLYNOMIAL_H

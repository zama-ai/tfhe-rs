#include <stdint.h>
extern "C" {
void cuda_fourier_transform_forward_as_torus_f128_async(
    void *stream, uint32_t gpu_index, void *re0, void *re1, void *im0,
    void *im1, void const *standard, uint32_t const N,
    const uint32_t number_of_samples);

void cuda_fourier_transform_forward_as_integer_f128_async(
    void *stream, uint32_t gpu_index, void *re0, void *re1, void *im0,
    void *im1, void const *standard, uint32_t const N,
    const uint32_t number_of_samples);

void cuda_fourier_transform_backward_as_torus_f128_async(
    void *stream, uint32_t gpu_index, void *standard, void const *re0,
    void const *re1, void const *im0, void const *im1, uint32_t const N,
    const uint32_t number_of_samples);
}

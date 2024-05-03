#ifndef TFHE_CUDA_BACKEND_POLYNOMIAL_H
#define TFHE_CUDA_BACKEND_POLYNOMIAL_H
template <typename T, typename ST>
void cuda_batch_convert_std_to_fft(cuda_stream_t *stream, double2 *dest,
                                   ST *src, uint32_t polynomial_size,
                                   uint32_t total_polynomials);
#endif // TFHE_CUDA_BACKEND_POLYNOMIAL_H

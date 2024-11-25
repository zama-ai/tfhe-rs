
extern "C" {
  void fourier_transform_forward_f128(void *stream, uint32_t gpu_index,
                                      void *re0, void *re1,
                                      void *im0, void *im1,
                                      void const *standard, uint32_t const N);
}
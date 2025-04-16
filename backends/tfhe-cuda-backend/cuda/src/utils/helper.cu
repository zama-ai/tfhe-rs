#include "helper.cuh"
template <> __global__ void print_debug_kernel(const double2 *src, int N) {
  for (int i = 0; i < N; i++) {
    printf("(%lf, %lf), ", src[i].x, src[i].y);
  }
}

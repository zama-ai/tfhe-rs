#ifndef KERNEL_DIMENSIONS_CUH
#define KERNEL_DIMENSIONS_CUH

inline int nextPow2(int x) {
  --x;
  x |= x >> 1;
  x |= x >> 2;
  x |= x >> 4;
  x |= x >> 8;
  x |= x >> 16;
  return ++x;
}

inline void getNumBlocksAndThreads(const int n, const int maxBlockSize,
                                   int &blocks, int &threads) {
  threads =
      (n < maxBlockSize * 2) ? max(128, nextPow2((n + 1) / 2)) : maxBlockSize;
  blocks = (n + threads - 1) / threads;
}

#endif // KERNEL_DIMENSIONS_H

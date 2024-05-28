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

// Determines blocks and threads in x for a given blockDim.y using the same
// logic than above
inline void getNumBlocksAndThreads2D(const int n, const int maxBlockSize,
                                     const int block_dim_y, int &blocks,
                                     int &threads_x) {
  const int max_block_dim_x = maxBlockSize / block_dim_y;
  threads_x = (n < max_block_dim_x * 2) ? max(128, nextPow2((n + 1) / 2))
                                        : max_block_dim_x;
  blocks = (n + threads_x - 1) / threads_x;
}

#endif // KERNEL_DIMENSIONS_H

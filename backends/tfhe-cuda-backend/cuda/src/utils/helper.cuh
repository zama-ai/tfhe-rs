#ifndef HELPER_CUH
#define HELPER_CUH

#include "device.h"
#include "helper_multi_gpu.h"
#include <cstdlib>
#include <cstring>

#define CEIL_DIV(M, N) (((M) + (N)-1) / (N))

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
  blocks = CEIL_DIV(n, threads);
}

// Determines blocks and threads in x for a given blockDim.y using the same
// logic than above
inline void getNumBlocksAndThreads2D(const int n, const int maxBlockSize,
                                     const int block_dim_y, int &blocks,
                                     int &threads_x) {
  const int max_block_dim_x = maxBlockSize / block_dim_y;
  threads_x = (n < max_block_dim_x * 2) ? max(128, nextPow2((n + 1) / 2))
                                        : max_block_dim_x;
  blocks = CEIL_DIV(n, threads_x);
}

// --------------------------------------------------------------------------
// Phase tokens for enforcing release ordering in memory structures.
//
// Usage in release() methods:
//   auto gpu_phase = GpuReleasePhase(streams);
//   device_buf.release(gpu_phase);          // GPU frees before sync
//   auto cpu_phase = std::move(gpu_phase).synchronize();
//   host_buf.release(cpu_phase);            // CPU frees after sync
// --------------------------------------------------------------------------

class CpuReleasePhase {
  friend class GpuReleasePhase;
  CpuReleasePhase() = default;

public:
  CpuReleasePhase(const CpuReleasePhase &) = delete;
  CpuReleasePhase &operator=(const CpuReleasePhase &) = delete;
  CpuReleasePhase(CpuReleasePhase &&) = default;
  CpuReleasePhase &operator=(CpuReleasePhase &&) = default;
};

class GpuReleasePhase {
  CudaStreams _streams;

public:
  GpuReleasePhase(CudaStreams streams) : _streams(streams) {}

  GpuReleasePhase(const GpuReleasePhase &) = delete;
  GpuReleasePhase &operator=(const GpuReleasePhase &) = delete;
  GpuReleasePhase(GpuReleasePhase &&) = default;
  GpuReleasePhase &operator=(GpuReleasePhase &&) = default;

  cudaStream_t stream() const { return _streams.stream(0); }
  uint32_t gpu_index() const { return _streams.gpu_index(0); }

  CpuReleasePhase synchronize() && {
    cuda_synchronize_stream(stream(), gpu_index());
    return CpuReleasePhase{};
  }
};

// --------------------------------------------------------------------------
// HostBuffer<T> — CPU staging buffer with bounds-checked indexing.
//
// Must be released via release(CpuReleasePhase&) before destruction.
// --------------------------------------------------------------------------

template <typename T> class HostBuffer {
  T *ptr = nullptr;
  size_t num_elements = 0;

public:
  HostBuffer() = default;

  HostBuffer(const HostBuffer &) = delete;
  HostBuffer &operator=(const HostBuffer &) = delete;

  HostBuffer(HostBuffer &&other) noexcept
      : ptr(other.ptr), num_elements(other.num_elements) {
    other.ptr = nullptr;
    other.num_elements = 0;
  }

  HostBuffer &operator=(HostBuffer &&other) noexcept {
    if (this != &other) {
      GPU_ASSERT(ptr == nullptr,
                 "HostBuffer assigned to without calling release()");
      ptr = other.ptr;
      num_elements = other.num_elements;
      other.ptr = nullptr;
      other.num_elements = 0;
    }
    return *this;
  }

  void allocate(size_t count) {
    GPU_ASSERT(ptr == nullptr,
               "HostBuffer::allocate called on non-null buffer");
    num_elements = count;
    ptr = static_cast<T *>(std::malloc(count * sizeof(T)));
    GPU_ASSERT(ptr != nullptr, "HostBuffer::allocate: malloc failed");
  }

  void allocate_zeroed(size_t count) {
    GPU_ASSERT(ptr == nullptr,
               "HostBuffer::allocate_zeroed called on non-null buffer");
    num_elements = count;
    ptr = static_cast<T *>(std::calloc(count, sizeof(T)));
    GPU_ASSERT(ptr != nullptr, "HostBuffer::allocate_zeroed: calloc failed");
  }

  T &operator[](size_t index) {
    GPU_ASSERT(index < num_elements,
               "HostBuffer: index %zu out of bounds (size %zu)", index,
               num_elements);
    return ptr[index];
  }

  const T &operator[](size_t index) const {
    GPU_ASSERT(index < num_elements,
               "HostBuffer: index %zu out of bounds (size %zu)", index,
               num_elements);
    return ptr[index];
  }

  T *data() { return ptr; }
  const T *data() const { return ptr; }
  size_t size() const { return num_elements; }

  void release(CpuReleasePhase &) {
    if (ptr) {
      std::free(ptr);
      ptr = nullptr;
      num_elements = 0;
    }
  }

  ~HostBuffer() {
    GPU_ASSERT(ptr == nullptr,
               "HostBuffer destroyed without calling release()");
  }
};

// --------------------------------------------------------------------------
// DeviceBuffer<T> — GPU buffer with phase-constrained release.
//
// Must be released via release(GpuReleasePhase&) before destruction.
// Use DeviceBuffer::borrow() for non-owning references (mem_reuse pattern).
// The allocate_gpu_memory flag is captured at allocation time and used
// automatically in copy, memset, and release operations.
// --------------------------------------------------------------------------

template <typename T> class DeviceBuffer {
  void *ptr = nullptr;
  size_t size_bytes = 0;
  bool owns = true;
  bool _allocate_gpu_memory = true;

public:
  DeviceBuffer() = default;

  DeviceBuffer(const DeviceBuffer &) = delete;
  DeviceBuffer &operator=(const DeviceBuffer &) = delete;

  DeviceBuffer(DeviceBuffer &&other) noexcept
      : ptr(other.ptr), size_bytes(other.size_bytes), owns(other.owns),
        _allocate_gpu_memory(other._allocate_gpu_memory) {
    other.ptr = nullptr;
    other.size_bytes = 0;
  }

  DeviceBuffer &operator=(DeviceBuffer &&other) noexcept {
    if (this != &other) {
      GPU_ASSERT(ptr == nullptr,
                 "DeviceBuffer assigned to without calling release()");
      ptr = other.ptr;
      size_bytes = other.size_bytes;
      owns = other.owns;
      _allocate_gpu_memory = other._allocate_gpu_memory;
      other.ptr = nullptr;
      other.size_bytes = 0;
    }
    return *this;
  }

  static DeviceBuffer borrow(const DeviceBuffer<T> &other) {
    DeviceBuffer buf;
    buf.ptr = other.ptr;
    buf.size_bytes = other.size_bytes;
    buf.owns = false;
    buf._allocate_gpu_memory = other._allocate_gpu_memory;
    return buf;
  }

  void allocate(size_t num_elements, CudaStreams streams,
                uint64_t &size_tracker, bool allocate_gpu_memory) {
    GPU_ASSERT(ptr == nullptr,
               "DeviceBuffer::allocate called on non-null buffer");
    size_bytes = num_elements * sizeof(T);
    _allocate_gpu_memory = allocate_gpu_memory;
    ptr = cuda_malloc_with_size_tracking_async(
        size_bytes, streams.stream(0), streams.gpu_index(0), size_tracker,
        allocate_gpu_memory);
    owns = true;
  }

  void copy_from_cpu_to_gpu_async(const HostBuffer<T> &src, size_t bytes,
                                  CudaStreams streams) {
    cuda_memcpy_with_size_tracking_async_to_gpu(
        ptr, src.data(), bytes, streams.stream(0), streams.gpu_index(0),
        _allocate_gpu_memory);
  }

  void copy_from_gpu_to_cpu_async(HostBuffer<T> &dst, size_t bytes,
                                  CudaStreams streams) {
    cuda_memcpy_async_to_cpu(dst.data(), ptr, bytes, streams.stream(0),
                             streams.gpu_index(0));
  }

  void memset_async(int value, size_t bytes, CudaStreams streams) {
    cuda_memset_with_size_tracking_async(ptr, value, bytes, streams.stream(0),
                                         streams.gpu_index(0),
                                         _allocate_gpu_memory);
  }

  void release(GpuReleasePhase &phase) {
    if (ptr && owns) {
      cuda_drop_with_size_tracking_async(ptr, phase.stream(), phase.gpu_index(),
                                         _allocate_gpu_memory);
    }
    ptr = nullptr;
    size_bytes = 0;
  }

  T *data() { return static_cast<T *>(ptr); }
  const T *data() const { return static_cast<const T *>(ptr); }
  size_t size() const { return size_bytes / sizeof(T); }
  bool is_owner() const { return owns; }
  bool allocate_gpu_memory() const { return _allocate_gpu_memory; }

  ~DeviceBuffer() {
    GPU_ASSERT(ptr == nullptr,
               "DeviceBuffer destroyed without calling release()");
  }
};

#endif // HELPER_CUH

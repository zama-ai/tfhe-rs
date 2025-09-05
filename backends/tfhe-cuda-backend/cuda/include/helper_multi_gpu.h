#ifndef HELPER_MULTI_GPU_H
#define HELPER_MULTI_GPU_H
#include <mutex>
#include <variant>
#include <vector>

#include "integer/integer.h"

extern std::mutex m;
extern bool p2p_enabled;
extern const int THRESHOLD_MULTI_GPU;

extern "C" {
int32_t cuda_setup_multi_gpu(int device_0_id);
}

// Define a variant type that can be either a vector or a single pointer
template <typename Torus>
using LweArrayVariant = std::variant<std::vector<Torus *>, Torus *>;

// Macro to define the visitor logic using std::holds_alternative for vectors
#define GET_VARIANT_ELEMENT(variant, index)                                    \
  [&] {                                                                        \
    if (std::holds_alternative<std::vector<Torus *>>(variant)) {               \
      return std::get<std::vector<Torus *>>(variant)[index];                   \
    } else {                                                                   \
      return std::get<Torus *>(variant);                                       \
    }                                                                          \
  }()
// Macro to define the visitor logic using std::holds_alternative for vectors
#define GET_VARIANT_ELEMENT_64BIT(variant, index)                              \
  [&] {                                                                        \
    if (std::holds_alternative<std::vector<uint64_t *>>(variant)) {            \
      return std::get<std::vector<uint64_t *>>(variant)[index];                \
    } else {                                                                   \
      return std::get<uint64_t *>(variant);                                    \
    }                                                                          \
  }()
uint32_t get_active_gpu_count(uint32_t num_inputs, uint32_t gpu_count);

int get_num_inputs_on_gpu(int total_num_inputs, int gpu_index, int gpu_count);

int get_gpu_offset(int total_num_inputs, int gpu_index, int gpu_count);


struct CudaStreams {
private:
  bool owns_streams = false;
  cudaStream_t const *_streams;
  uint32_t const *_gpu_indexes;
  uint32_t _gpu_count;

  CudaStreams(cudaStream_t const *streams, uint32_t const *gpu_indexes, uint32_t gpu_count)
      : _streams(streams), _gpu_indexes(gpu_indexes), _gpu_count(gpu_count) {
  }

public:

  CudaStreams() : _streams(nullptr), _gpu_indexes(nullptr), _gpu_count((uint32_t)-1) { }

  CudaStreams active_gpu_subset(int num_radix_blocks)
  {
    return CudaStreams {
      _streams,
      _gpu_indexes,
      get_active_gpu_count(num_radix_blocks, _gpu_count)
  };
  }

  CudaStreams subset_first_gpu() const
  {
    return CudaStreams {
      _streams,
      _gpu_indexes,
      1
    };
  }

  GpuBoundStream get(uint32_t idx)  {
    return GpuBoundStream { _streams[idx], _gpu_indexes[idx] };
  }

  void synchronize() const {
    for (uint i = 0; i < _gpu_count; i++) {
      cuda_synchronize_stream(_streams[i], _gpu_indexes[i]);
    }
  }

  cudaStream_t const *streams() const { return _streams; }

  uint32_t const *gpu_indexes() const { return _gpu_indexes; }

  cudaStream_t stream(uint32_t idx) const { return _streams[idx]; }
  uint32_t gpu_index(uint32_t idx) const { return _gpu_indexes[idx]; }
  uint32_t count() const { return _gpu_count; }

  CudaStreams(CudaStreamsFFI &ffi)
      : _streams((cudaStream_t *)ffi.streams), _gpu_indexes(ffi.gpu_indexes),
        _gpu_count(ffi.gpu_count) {}

  CudaStreams clone() const
  {
    cudaStream_t* streams_clone = new cudaStream_t[_gpu_count];
    uint32_t* gpu_indexes_clone = new uint32_t[_gpu_count];
    for (int i = 0; i < _gpu_count; ++i) {
      streams_clone[i] = cuda_create_stream(_gpu_indexes[i]);
      gpu_indexes_clone[i] = _gpu_indexes[i];
    }
    CudaStreams res(
       streams_clone,
       gpu_indexes_clone,
       _gpu_count);
    res.owns_streams = true;
    return res;
  }

  void destroy()
  {
    if (owns_streams)
    {
      for (int i = 0; i < _gpu_count; ++i) {
        cuda_destroy_stream(_streams[i], _gpu_indexes[i]);
      }
      delete _streams;
      _streams = nullptr;
      delete _gpu_indexes;
      _gpu_indexes = nullptr;
    }
  }

  ~CudaStreams()
  {
    GPU_ASSERT(!owns_streams || _streams == nullptr, "Destroy was not called on a CudaStreams object that is a clone of another one");
  }
};

#endif

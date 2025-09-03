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

/// get_variant_element() resolves access when the input may be either a single
/// pointer or a vector of pointers. If the variant holds a single pointer, the
/// index is ignored and that pointer is returned; if it holds a vector, the
/// element at `index` is returned.
///
/// This function replaces the previous macro:
/// - Easier to debug and read than a macro
/// - Deduces the pointer type from the variant (no need to name a Torus type
/// explicitly)
/// - Defined in a header, so it’s eligible for inlining by the optimizer
template <typename Torus>
inline Torus
get_variant_element(const std::variant<std::vector<Torus>, Torus> &variant,
                    size_t index) {
  if (std::holds_alternative<std::vector<Torus>>(variant)) {
    return std::get<std::vector<Torus>>(variant)[index];
  } else {
    return std::get<Torus>(variant);
  }
}

uint32_t get_active_gpu_count(uint32_t num_inputs, uint32_t gpu_count);

int get_num_inputs_on_gpu(int total_num_inputs, int gpu_index, int gpu_count);

int get_gpu_offset(int total_num_inputs, int gpu_index, int gpu_count);

struct CudaStreams {
private:
  cudaStream_t const *_streams;
  uint32_t const *_gpu_indexes;
  uint32_t _gpu_count;
  bool _owns_streams;

  CudaStreams(cudaStream_t const *streams, uint32_t const *gpu_indexes,
              uint32_t gpu_count)
      : _streams(streams), _gpu_indexes(gpu_indexes), _gpu_count(gpu_count),
        _owns_streams(false) {}

public:
  CudaStreams()
      : _streams(nullptr), _gpu_indexes(nullptr), _gpu_count((uint32_t)-1),
        _owns_streams(false) {}

  CudaStreams active_gpu_subset(int num_radix_blocks) {
    return CudaStreams(_streams, _gpu_indexes,
                       get_active_gpu_count(num_radix_blocks, _gpu_count));
  }

  CudaStreams subset_first_gpu() const {
    return CudaStreams(_streams, _gpu_indexes, 1);
  }

  void synchronize() const {
    for (uint32_t i = 0; i < _gpu_count; i++) {
      cuda_synchronize_stream(_streams[i], _gpu_indexes[i]);
    }
  }

  cudaStream_t stream(uint32_t idx) const {
    GPU_ASSERT(idx < _gpu_count, "Invalid GPU index");
    return _streams[idx];
  }
  uint32_t gpu_index(uint32_t idx) const {
    GPU_ASSERT(idx < _gpu_count, "Invalid GPU index");
    return _gpu_indexes[idx];
  }
  uint32_t count() const { return _gpu_count; }

  CudaStreams(CudaStreamsFFI &ffi)
      : _streams((cudaStream_t *)ffi.streams), _gpu_indexes(ffi.gpu_indexes),
        _gpu_count(ffi.gpu_count), _owns_streams(false) {}

  void assign_clone(const CudaStreams &other) {
    GPU_ASSERT(_streams == nullptr, "Assign clone to non-empty cudastreams");

    cudaStream_t *streams_clone = new cudaStream_t[other._gpu_count];
    printf("Clone CudaStreams orig %p, new %p  (this=%p)\n", this->_streams,
           streams_clone, this);

    uint32_t *gpu_indexes_clone = new uint32_t[_gpu_count];
    for (uint32_t i = 0; i < other._gpu_count; ++i) {
      streams_clone[i] = cuda_create_stream(other._gpu_indexes[i]);
      gpu_indexes_clone[i] = other._gpu_indexes[i];
    }

    this->_streams = streams_clone;
    this->_gpu_indexes = gpu_indexes_clone;
    this->_gpu_count = other._gpu_count;
    this->_owns_streams = true;
  }

  CudaStreams(const CudaStreams &src)
      : _streams(src._streams), _gpu_indexes(src._gpu_indexes),
        _gpu_count(src._gpu_count), _owns_streams(false) {}

  CudaStreams &operator=(CudaStreams const &other) {
    GPU_ASSERT(this->_streams == nullptr || this->_streams == other._streams,
               "Assigning an already initialized CudaStreams");
    this->_streams = other._streams;
    this->_gpu_indexes = other._gpu_indexes;
    this->_gpu_count = other._gpu_count;
    this->_owns_streams = false;
    return *this;
  }

  void destroy() {
    if (_owns_streams) {
      for (uint32_t i = 0; i < _gpu_count; ++i) {
        cuda_destroy_stream(_streams[i], _gpu_indexes[i]);
      }
      delete[] _streams;
      _streams = nullptr;
      delete[] _gpu_indexes;
      _gpu_indexes = nullptr;
    }
  }

  ~CudaStreams() {
    GPU_ASSERT(!_owns_streams || _streams == nullptr,
               "Destroy  (this=%p) was not called on a CudaStreams object that "
               "is a clone "
               "of another one, %p",
               this, this->_streams);
  }
};

#endif

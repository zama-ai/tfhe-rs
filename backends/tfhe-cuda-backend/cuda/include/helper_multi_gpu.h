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

// A Set of GPU Streams and associated GPUs
// Can be constructed from the FFI struct CudaStreamsFFI which
// is only used to pass the streams/gpus at the rust/C interface
// This class should only be constructed from the FFI struct,
// through class methods or through the copy constructor. The class
// can also be constructed as an empty set
struct CudaStreams {
private:
  cudaStream_t const *_streams;
  uint32_t const *_gpu_indexes;
  uint32_t _gpu_count;
  bool _owns_streams;

  // Prevent the construction of a CudaStreams class from user-code
  CudaStreams(cudaStream_t const *streams, uint32_t const *gpu_indexes,
              uint32_t gpu_count)
      : _streams(streams), _gpu_indexes(gpu_indexes), _gpu_count(gpu_count),
        _owns_streams(false) {}

public:
  // Construct an empty set. Invalid use of an empty set should raise an error
  // right away through asserts or because of a nullptr dereference
  CudaStreams()
      : _streams(nullptr), _gpu_indexes(nullptr), _gpu_count((uint32_t)-1),
        _owns_streams(false) {}

  // Returns a subset of this set as an active subset. An active subset is one
  // that is temporarily used to perform some computation
  CudaStreams active_gpu_subset(int num_radix_blocks) {
    return CudaStreams(_streams, _gpu_indexes,
                       get_active_gpu_count(num_radix_blocks, _gpu_count));
  }

  // Returns a CudaStreams struct containing only the ith stream
  CudaStreams get_ith(int i) const {
    return CudaStreams(&_streams[i], &_gpu_indexes[i], 1);
  }

  // Synchronize all the streams in the set
  void synchronize() const {
    for (uint32_t i = 0; i < _gpu_count; i++) {
      cuda_synchronize_stream(_streams[i], _gpu_indexes[i]);
    }
  }

  cudaStream_t stream(uint32_t idx) const {
    PANIC_IF_FALSE(idx < _gpu_count, "Invalid GPU index");
    return _streams[idx];
  }
  uint32_t gpu_index(uint32_t idx) const {
    PANIC_IF_FALSE(idx < _gpu_count, "Invalid GPU index");
    return _gpu_indexes[idx];
  }
  uint32_t count() const { return _gpu_count; }

  // Construct from the rust FFI stream set. Streams are created in rust
  // using the bindings.
  CudaStreams(CudaStreamsFFI &ffi)
      : _streams((cudaStream_t *)ffi.streams), _gpu_indexes(ffi.gpu_indexes),
        _gpu_count(ffi.gpu_count), _owns_streams(false) {}

  // Create a new set of streams on the same gpus as those of the current stream
  // set Can be used to parallelize computation by issuing kernels on multiple
  // streams on the same GPU
  void create_on_same_gpus(const CudaStreams &other) {
    PANIC_IF_FALSE(_streams == nullptr,
                   "Assign clone to non-empty cudastreams");

    cudaStream_t *new_streams = new cudaStream_t[other._gpu_count];

    uint32_t *gpu_indexes_clone = new uint32_t[_gpu_count];
    for (uint32_t i = 0; i < other._gpu_count; ++i) {
      new_streams[i] = cuda_create_stream(other._gpu_indexes[i]);
      gpu_indexes_clone[i] = other._gpu_indexes[i];
    }

    this->_streams = new_streams;
    this->_gpu_indexes = gpu_indexes_clone;
    this->_gpu_count = other._gpu_count;

    // Flag this instance as owning streams so that we can destroy
    // the streams when they aren't needed anymore
    this->_owns_streams = true;
  }

  // Copy constructor, setting the own flag to false
  // Only the initial instance of CudaStreams created with
  // assign_clone owns streams, all copies of it do not own the
  // streams
  CudaStreams(const CudaStreams &src)
      : _streams(src._streams), _gpu_indexes(src._gpu_indexes),
        _gpu_count(src._gpu_count), _owns_streams(false) {}

  CudaStreams &operator=(CudaStreams const &other) {
    PANIC_IF_FALSE(this->_streams == nullptr ||
                       this->_streams == other._streams,
                   "Assigning an already initialized CudaStreams");
    this->_streams = other._streams;
    this->_gpu_indexes = other._gpu_indexes;
    this->_gpu_count = other._gpu_count;

    // Only the initial instance of CudaStreams created with
    // assign_clone owns streams, all copies of it do not own the
    // streams
    this->_owns_streams = false;
    return *this;
  }

  // Destroy the streams if they are created by assign_clone.
  // We require the developer to call `destroy` on all instances
  // of cloned streams.
  void release() {
    // If this instance doesn't own streams, there's nothing to do
    // as the streams were created on the Rust side.
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

  // The destructor checks that streams created with assign_clone
  // were destroyed manually with `destroy`.
  ~CudaStreams() {
    // Ensure streams are destroyed
    PANIC_IF_FALSE(
        !_owns_streams || _streams == nullptr,
        "Destroy  (this=%p) was not called on a CudaStreams object that "
        "is a clone "
        "of another one, %p",
        this, this->_streams);
  }
};

struct CudaStreamsWorkersWaitFirstBarrier {
private:
  cudaEvent_t _event;
  CudaStreams _streams;

  CudaStreamsWorkersWaitFirstBarrier(
      const CudaStreamsWorkersWaitFirstBarrier &) {
  } // Prevent copy-construction
  CudaStreamsWorkersWaitFirstBarrier &
  operator=(const CudaStreamsWorkersWaitFirstBarrier &) {
    return *this;
  } // Prevent assignment
public:
  void create_on(const CudaStreams &streams) {
    _streams = streams;
    _event = cuda_create_event(streams.gpu_index(0));
  }

  CudaStreamsWorkersWaitFirstBarrier() { _event = nullptr; };

  void workers_wait_for_gpu_0() {
    GPU_ASSERT(
        _event != nullptr,
        "CudaStreamsWorkersWaitFirstBarrier: must call create_on before use");

    if (_streams.count() > 1) {
      cuda_event_record(_event, _streams.stream(0), _streams.gpu_index(0));
      for (int j = 1; j < _streams.count(); j++) {
        cuda_stream_wait_event(_streams.stream(j), _event,
                               _streams.gpu_index(j));
      }
    }
  }

  void user_streams_wait_for_gpu_0(const CudaStreams &user_streams) {
    GPU_ASSERT(
        _event != nullptr,
        "CudaStreamsWorkersWaitFirstBarrier: must call create_on before use");

    cuda_event_record(_event, _streams.stream(0), _streams.gpu_index(0));
    for (int j = 0; j < user_streams.count(); j++) {
      cuda_stream_wait_event(user_streams.stream(j), _event,
                             user_streams.gpu_index(j));
    }
  }

  void release() {
    cuda_event_destroy(_event, _streams.gpu_index(0));
    _event = nullptr;
  }

  ~CudaStreamsWorkersWaitFirstBarrier() {
    GPU_ASSERT(_event == nullptr, "CudaStreamsWorkersWaitFirstBarrier: must "
                                  "call release before destruction");
  }
};

struct CudaStreamsFirstWaitsWorkersBarrier {
private:
  std::vector<cudaEvent_t> _events;
  CudaStreams _streams;

  CudaStreamsFirstWaitsWorkersBarrier(
      const CudaStreamsFirstWaitsWorkersBarrier &) {
  } // Prevent copy-construction
  CudaStreamsFirstWaitsWorkersBarrier &
  operator=(const CudaStreamsFirstWaitsWorkersBarrier &) {
    return *this;
  } // Prevent assignment
public:
  void create_on(const CudaStreams &streams) {
    GPU_ASSERT(streams.count() > 1, "CudaStreamsFirstWaitsWorkersBarrier: "
                                    "Attempted to create on single GPU");
    _streams = streams;
    _events.resize(streams.count());
    for (int i = 0; i < streams.count(); i++) {
      _events[i] = cuda_create_event(streams.gpu_index(i));
    }
  }

  CudaStreamsFirstWaitsWorkersBarrier(){};

  void gpu_0_wait_for_workers() {
    GPU_ASSERT(
        !_events.empty(),
        "CudaStreamsFirstWaitsWorkersBarrier: must call create_on before use");

    if (_streams.count() > 1) {
      // Worker GPUs record their events
      for (int j = 1; j < _streams.count(); j++) {
        cuda_event_record(_events[j], _streams.stream(j),
                          _streams.gpu_index(j));
      }

      // GPU 0 waits for all workers
      for (int j = 1; j < _streams.count(); j++) {
        cuda_stream_wait_event(_streams.stream(0), _events[j],
                               _streams.gpu_index(0));
      }
    }
  }

  void release() {
    for (int j = 0; j < _streams.count(); j++) {
      cuda_event_destroy(_events[j], _streams.gpu_index(j));
    }

    _events.clear();
  }

  ~CudaStreamsFirstWaitsWorkersBarrier() {
    GPU_ASSERT(_events.empty(),
               "CudaStreamsFirstWaitsWorkersBarrier: must "
               "call release before destruction: events size = %lu",
               _events.size());
  }
};

#endif

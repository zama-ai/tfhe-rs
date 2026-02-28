#ifndef HELPER_MULTI_GPU_H
#define HELPER_MULTI_GPU_H
#include <mutex>
#include <variant>
#include <vector>

#include "integer/integer.h"

extern std::mutex m;
extern bool p2p_enabled;
extern const int THRESHOLD_MULTI_GPU_WITH_MULTI_BIT_PARAMS;
extern const int THRESHOLD_MULTI_GPU_WITH_CLASSICAL_PARAMS_U128;

// Returns the threshold for multi-GPU with classical params.
// Computed once based on GPU 0's compute capability and SM count.
int get_threshold_multi_gpu_classical();
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

uint32_t get_active_gpu_count(uint32_t num_inputs, uint32_t gpu_count,
                              PBS_TYPE pbs_type);
uint32_t get_active_gpu_count_u128(uint32_t num_inputs, uint32_t gpu_count,
                                   PBS_TYPE pbs_type);

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
      : _streams(nullptr), _gpu_indexes(nullptr), _gpu_count(0),
        _owns_streams(false) {}

  // Returns a subset of this set as an active subset. An active subset is one
  // that is temporarily used to perform some computation
  CudaStreams active_gpu_subset(int num_radix_blocks, PBS_TYPE pbs_type) {
    return CudaStreams(
        _streams, _gpu_indexes,
        get_active_gpu_count(num_radix_blocks, _gpu_count, pbs_type));
  }
  // Returns a subset of this set as an active subset for pbs128. An active
  // subset is one that is temporarily used to perform some computation. For
  // pbs128, the threshold is different, because the original threshold was
  // designed for 2_2 params.
  CudaStreams active_gpu_subset_u128(int num_radix_blocks, PBS_TYPE pbs_type) {
    return CudaStreams(
        _streams, _gpu_indexes,
        get_active_gpu_count_u128(num_radix_blocks, _gpu_count, pbs_type));
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
                   "Cuda error: Assign clone to non-empty CudaStreams");
    PANIC_IF_FALSE(_gpu_count <= 8,
                   "Cuda error: GPU count should be in the interval [0, 8]");

    cudaStream_t *new_streams = new cudaStream_t[other._gpu_count];

    uint32_t *gpu_indexes_clone = new uint32_t[other._gpu_count];
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
    /*    PANIC_IF_FALSE(this->_streams == nullptr ||
                           this->_streams == other._streams,
                       "Assigning an already initialized CudaStreams");*/
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
      _gpu_count = 0;
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

struct InternalCudaStreams {
private:
  CudaStreams *_internal_cuda_streams;
  uint32_t _num_internal_cuda_streams;
  uint32_t _num_gpus;

  cudaEvent_t _incoming_event;
  cudaEvent_t *_outgoing_events;

  InternalCudaStreams(const InternalCudaStreams &) = delete;
  InternalCudaStreams &operator=(const InternalCudaStreams &) = delete;

public:
  InternalCudaStreams() {
    _internal_cuda_streams = nullptr;
    _incoming_event = nullptr;
    _outgoing_events = nullptr;
    _num_internal_cuda_streams = 0;
    _num_gpus = 0;
  }

  void create_internal_cuda_streams_on_same_gpus(
      const CudaStreams &base_streams, uint32_t num_internal_cuda_streams) {

    PANIC_IF_FALSE(_internal_cuda_streams == nullptr,
                   "InternalCudaStreams: object already initialized.");

    _num_internal_cuda_streams = num_internal_cuda_streams;
    _num_gpus = base_streams.count();

    if (num_internal_cuda_streams > 0) {
      _internal_cuda_streams = new CudaStreams[num_internal_cuda_streams];
      for (uint32_t i = 0; i < num_internal_cuda_streams; ++i) {
        _internal_cuda_streams[i].create_on_same_gpus(base_streams);
      }
    }

    if (_num_gpus > 0) {
      _incoming_event = cuda_create_event(base_streams.gpu_index(0));
    }

    uint32_t total_events = num_internal_cuda_streams * _num_gpus;

    if (total_events > 0) {
      _outgoing_events = new cudaEvent_t[total_events];
      for (uint32_t s = 0; s < num_internal_cuda_streams; ++s) {
        for (uint32_t g = 0; g < _num_gpus; ++g) {
          _outgoing_events[s * _num_gpus + g] =
              cuda_create_event(base_streams.gpu_index(g));
        }
      }
    }
  }

  CudaStreams &operator[](uint32_t idx) const {
    PANIC_IF_FALSE(idx < _num_internal_cuda_streams,
                   "InternalCudaStreams index out of bounds");
    return _internal_cuda_streams[idx];
  }

  uint32_t num_streams() const { return _num_internal_cuda_streams; }

  void
  internal_streams_wait_for_main_stream_0(const CudaStreams &main_streams) {

    PANIC_IF_FALSE(main_streams.gpu_index(0) ==
                       _internal_cuda_streams[0].gpu_index(0),
                   "InternalCudaStreams: gpu_index(0) of main_streams should "
                   "be the same as _internal_cuda_streams[0].");

    cuda_event_record(_incoming_event, main_streams.stream(0),
                      main_streams.gpu_index(0));

    for (uint32_t s = 0; s < _num_internal_cuda_streams; ++s) {
      for (uint32_t g = 0; g < _num_gpus; ++g) {
        cuda_stream_wait_event(_internal_cuda_streams[s].stream(g),
                               _incoming_event,
                               _internal_cuda_streams[s].gpu_index(g));
      }
    }
  }

  void
  internal_streams_slice_wait_for_main_stream_0(const CudaStreams &main_streams,
                                                const uint32_t *stream_indices,
                                                size_t num_indices) {

    PANIC_IF_FALSE(main_streams.gpu_index(0) ==
                       _internal_cuda_streams[0].gpu_index(0),
                   "InternalCudaStreams: gpu_index(0) of main_streams should "
                   "be the same as _internal_cuda_streams[0].");

    cuda_event_record(_incoming_event, main_streams.stream(0),
                      main_streams.gpu_index(0));

    for (size_t i = 0; i < num_indices; ++i) {
      uint32_t s_idx = stream_indices[i];
      PANIC_IF_FALSE(s_idx < _num_internal_cuda_streams,
                     "InternalCudaStreams: stream index out of bounds");

      for (uint32_t g = 0; g < _num_gpus; ++g) {
        cuda_stream_wait_event(_internal_cuda_streams[s_idx].stream(g),
                               _incoming_event,
                               _internal_cuda_streams[s_idx].gpu_index(g));
      }
    }
  }

  void
  main_stream_0_wait_for_internal_streams(const CudaStreams &main_streams) {

    PANIC_IF_FALSE(main_streams.gpu_index(0) ==
                       _internal_cuda_streams[0].gpu_index(0),
                   "InternalCudaStreams: gpu_index(0) of main_streams should "
                   "be the same as _internal_cuda_streams[0].");

    for (uint32_t s = 0; s < _num_internal_cuda_streams; ++s) {
      for (uint32_t g = 0; g < _num_gpus; ++g) {
        cuda_event_record(_outgoing_events[s * _num_gpus + g],
                          _internal_cuda_streams[s].stream(g),
                          _internal_cuda_streams[s].gpu_index(g));
      }
    }

    for (uint32_t s = 0; s < _num_internal_cuda_streams; ++s) {
      for (uint32_t g = 0; g < _num_gpus; ++g) {
        cuda_stream_wait_event(main_streams.stream(0),
                               _outgoing_events[s * _num_gpus + g],
                               main_streams.gpu_index(0));
      }
    }
  }

  void
  main_stream_0_wait_for_internal_streams_slice(const CudaStreams &main_streams,
                                                const uint32_t *stream_indices,
                                                size_t num_indices) {

    PANIC_IF_FALSE(main_streams.gpu_index(0) ==
                       _internal_cuda_streams[0].gpu_index(0),
                   "InternalCudaStreams: gpu_index(0) of main_streams should "
                   "be the same as _internal_cuda_streams[0].");

    for (size_t i = 0; i < num_indices; ++i) {
      uint32_t s_idx = stream_indices[i];
      PANIC_IF_FALSE(s_idx < _num_internal_cuda_streams,
                     "InternalCudaStreams: stream index out of bounds");

      for (uint32_t g = 0; g < _num_gpus; ++g) {
        cuda_event_record(_outgoing_events[s_idx * _num_gpus + g],
                          _internal_cuda_streams[s_idx].stream(g),
                          _internal_cuda_streams[s_idx].gpu_index(g));
      }
    }

    for (size_t i = 0; i < num_indices; ++i) {
      uint32_t s_idx = stream_indices[i];
      for (uint32_t g = 0; g < _num_gpus; ++g) {
        cuda_stream_wait_event(main_streams.stream(0),
                               _outgoing_events[s_idx * _num_gpus + g],
                               main_streams.gpu_index(0));
      }
    }
  }

  void release(const CudaStreams &main_streams) {

    PANIC_IF_FALSE(main_streams.gpu_index(0) ==
                       _internal_cuda_streams[0].gpu_index(0),
                   "InternalCudaStreams: gpu_index(0) of main_streams should "
                   "be the same as _internal_cuda_streams[0].");

    cuda_synchronize_stream(main_streams.stream(0), main_streams.gpu_index(0));

    if (_outgoing_events && _internal_cuda_streams) {
      for (uint32_t s = 0; s < _num_internal_cuda_streams; ++s) {
        for (uint32_t g = 0; g < _num_gpus; ++g) {
          cuda_event_destroy(_outgoing_events[s * _num_gpus + g],
                             _internal_cuda_streams[s].gpu_index(g));
        }
      }
      delete[] _outgoing_events;
      _outgoing_events = nullptr;
    }

    if (_incoming_event && _internal_cuda_streams) {
      cuda_event_destroy(_incoming_event,
                         _internal_cuda_streams[0].gpu_index(0));
      _incoming_event = nullptr;
    }

    if (_internal_cuda_streams) {
      for (uint32_t i = 0; i < _num_internal_cuda_streams; ++i) {
        _internal_cuda_streams[i].release();
      }
      delete[] _internal_cuda_streams;
      _internal_cuda_streams = nullptr;
    }
  }

  ~InternalCudaStreams() {
    PANIC_IF_FALSE(_internal_cuda_streams == nullptr &&
                       _incoming_event == nullptr &&
                       _outgoing_events == nullptr,
                   "InternalCudaStreams: must call release before destruction");
  }
};

struct CudaStreamsBarrier {
private:
  std::vector<cudaEvent_t> _events;
  CudaStreams _streams;

  CudaStreamsBarrier(const CudaStreamsBarrier &) {} // Prevent copy-construction
  CudaStreamsBarrier &operator=(const CudaStreamsBarrier &) {
    return *this;
  } // Prevent assignment
public:
  void create_on(const CudaStreams &streams) {
    _streams = streams;

    GPU_ASSERT(streams.count() > 1, "CudaStreamsFirstWaitsWorkersBarrier: "
                                    "Attempted to create on single GPU");
    _events.resize(streams.count());
    for (int i = 0; i < streams.count(); i++) {
      _events[i] = cuda_create_event(streams.gpu_index(i));
    }
  }

  CudaStreamsBarrier(){};

  void local_streams_wait_for_stream_0(const CudaStreams &user_streams) {
    GPU_ASSERT(!_events.empty(),
               "CudaStreamsBarrier: must call create_on before use");
    GPU_ASSERT(user_streams.gpu_index(0) == _streams.gpu_index(0),
               "CudaStreamsBarrier: synchronization can only be performed on "
               "the GPUs the barrier was initially created on.");

    cuda_event_record(_events[0], user_streams.stream(0),
                      user_streams.gpu_index(0));
    for (int j = 1; j < user_streams.count(); j++) {
      GPU_ASSERT(user_streams.gpu_index(j) == _streams.gpu_index(j),
                 "CudaStreamsBarrier: synchronization can only be performed on "
                 "the GPUs the barrier was initially created on.");
      cuda_stream_wait_event(user_streams.stream(j), _events[0],
                             user_streams.gpu_index(j));
    }
  }

  void stream_0_wait_for_local_streams(const CudaStreams &user_streams) {
    GPU_ASSERT(
        !_events.empty(),
        "CudaStreamsFirstWaitsWorkersBarrier: must call create_on before use");
    GPU_ASSERT(
        user_streams.count() <= _events.size(),
        "CudaStreamsFirstWaitsWorkersBarrier: trying to synchronize too many "
        "streams. "
        "The barrier was created on a LUT that had %lu active streams, while "
        "the user stream set has %u streams",
        _events.size(), user_streams.count());

    if (user_streams.count() > 1) {
      // Worker GPUs record their events
      for (int j = 1; j < user_streams.count(); j++) {
        GPU_ASSERT(_streams.gpu_index(j) == user_streams.gpu_index(j),
                   "CudaStreamsBarrier: The user stream "
                   "set GPU[%d]=%u while the LUT stream set GPU[%d]=%u",
                   j, user_streams.gpu_index(j), j, _streams.gpu_index(j));

        cuda_event_record(_events[j], user_streams.stream(j),
                          user_streams.gpu_index(j));
      }

      // GPU 0 waits for all workers
      for (int j = 1; j < user_streams.count(); j++) {
        cuda_stream_wait_event(user_streams.stream(0), _events[j],
                               user_streams.gpu_index(0));
      }
    }
  }

  void release() {
    for (int j = 0; j < _streams.count(); j++) {
      cuda_event_destroy(_events[j], _streams.gpu_index(j));
    }

    _events.clear();
  }

  ~CudaStreamsBarrier() {
    GPU_ASSERT(_events.empty(),
               "CudaStreamsBarrier: must "
               "call release before destruction: events size = %lu",
               _events.size());
  }
};

// Event pool for managing temporary CUDA events in scatter/gather operations
struct CudaEventPool {
private:
  std::vector<cudaEvent_t> _events;
  std::vector<uint32_t> _gpu_indices;

public:
  CudaEventPool() {}

  // Requests a new event from the pool (creates and stores it)
  cudaEvent_t request_event(uint32_t gpu_index) {
    cudaEvent_t event = cuda_create_event(gpu_index);
    _events.push_back(event);
    _gpu_indices.push_back(gpu_index);
    return event;
  }

  // Releases all pooled events
  // This should always be called in the release of the LUT, so streams
  // are already synchronized
  void release() {
    for (size_t i = 0; i < _events.size(); i++) {
      cuda_event_destroy(_events[i], _gpu_indices[i]);
    }
    _events.clear();
    _gpu_indices.clear();
  }

  ~CudaEventPool() {
    GPU_ASSERT(_events.empty(),
               "CudaEventPool: must call release before destruction");
  }
};

#endif

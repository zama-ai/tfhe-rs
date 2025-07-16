#ifndef HELPER_MULTI_GPU_H
#define HELPER_MULTI_GPU_H
#include <mutex>
#include <variant>
#include <vector>

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
int get_active_gpu_count(int num_inputs, int gpu_count);

int get_num_inputs_on_gpu(int total_num_inputs, int gpu_index, int gpu_count);

int get_gpu_offset(int total_num_inputs, int gpu_index, int gpu_count);

#endif

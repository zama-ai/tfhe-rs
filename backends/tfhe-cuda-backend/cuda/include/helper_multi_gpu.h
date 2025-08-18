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

int get_active_gpu_count(int num_inputs, int gpu_count);

int get_num_inputs_on_gpu(int total_num_inputs, int gpu_index, int gpu_count);

int get_gpu_offset(int total_num_inputs, int gpu_index, int gpu_count);

#endif

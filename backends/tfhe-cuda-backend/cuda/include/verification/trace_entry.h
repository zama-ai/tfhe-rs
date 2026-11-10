#ifndef CUDA_VERIFICATION_TRACE_ENTRY_H
#define CUDA_VERIFICATION_TRACE_ENTRY_H

// Entry points recording verification traces of integer ops (test builds
// only, see verification/trace.h). Each one runs the op through its FFI
// functions (scratch, op, cleanup) for every value of its public parameters
// and writes one text trace per configuration.

#include <stdint.h>

extern "C" {

/// @brief Records host_add_and_propagate_single_carry on num_blocks blocks
/// with the GPU default 2_2 parameters, for requested_flag in {NONE, OVERFLOW,
/// CARRY} x uses_carry in {0, 1}: six traces written to
/// out_dir/add_and_propagate_single_carry_b<n>_flag_<f>_carry<c>.trace.
///
/// Keys and inputs are zero: the recorded algorithm does not depend on data.
///
/// @return the number of traces written
uint32_t cuda_verification_trace_add_and_propagate_single_carry_64(
    const char *out_dir, uint32_t gpu_index, uint32_t num_blocks);
}

#endif // CUDA_VERIFICATION_TRACE_ENTRY_H

// Records the verification traces of the integer ops (VERIFICATION_TRACE
// builds only).
//
//   usage: verification_trace <out_dir> [num_blocks = 32] [gpu_index = 0]
#include "verification/trace_entry.h"
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <system_error>

int main(int argc, char **argv) {
  if (argc < 2) {
    std::fprintf(stderr,
                 "usage: %s <out_dir> [num_blocks = 32] [gpu_index = 0]\n",
                 argv[0]);
    return 1;
  }
  const char *out_dir = argv[1];
  uint32_t num_blocks = argc > 2 ? (uint32_t)std::atoi(argv[2]) : 32;
  uint32_t gpu_index = argc > 3 ? (uint32_t)std::atoi(argv[3]) : 0;

  std::error_code error;
  std::filesystem::create_directories(out_dir, error);
  if (error) {
    std::fprintf(stderr, "cannot create %s: %s\n", out_dir,
                 error.message().c_str());
    return 1;
  }

  uint32_t written = cuda_verification_trace_add_and_propagate_single_carry_64(
      out_dir, gpu_index, num_blocks);
  std::printf("add_and_propagate_single_carry: %u traces written to %s\n",
              written, out_dir);
  return 0;
}

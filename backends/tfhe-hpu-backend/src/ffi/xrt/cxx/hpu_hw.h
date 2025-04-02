#pragma once
#include "rust/cxx.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <memory>
#include <queue>


// XRT includes
#include "experimental/xrt_bo.h"
#include "experimental/xrt_ip.h"
#include "experimental/xrt_device.h"
#include "experimental/xrt_xclbin.h"

#include "tfhe-hpu-backend/src/ffi/xrt/cxx/mem_zone.h"

// Utilities macro to handle verbosity
#define pr_trace(verbose, stmts)\
  if (verbose >= VerbosityCxx::Trace) { \
  std::cout << "cxx::Trace: " << stmts;\
  }
#define pr_debug(verbose, stmts)\
  if (verbose >= VerbosityCxx::Debug) { \
  std::cout << "cxx::Debug: " << stmts;\
  }
#define pr_info(verbose, stmts)\
  if (verbose >= VerbosityCxx::Info) { \
  std::cout << "cxx::Info: " << stmts;\
  }
#define pr_warn(verbose, stmts)\
  if (verbose >= VerbosityCxx::Warning) { \
  std::cout << "cxx::Warning: " << stmts;\
  }
#define pr_err(verbose, stmts)\
  if (verbose >= VerbosityCxx::Error) { \
  std::cerr << "cxx::Error: " << stmts;\
  }

// Some Arch related defined
#define MEM_BANK_SIZE_MiB 512
#define MEM_CHUNK_SIZE_B ((size_t)(16*1024*1024))

namespace ffi {
    // Forward definition: Concrete implementation is made by Cxx
    enum class SyncModeCxx: uint8_t;
    enum class VerbosityCxx: uint8_t;
    class MemZonePropertiesCxx;

    class HpuHw {
      public:
        HpuHw(uint32_t fpga_id, rust::String kernel_name, rust::String xclbin_name, VerbosityCxx verbose);
        ~HpuHw();

      private:
        const uint32_t fpga_id;
        const std::string kernel_name;
        const std::string xclbin_name;
        const VerbosityCxx verbose;

        // XRT objects
        xrt::device fpga;
        xrt::ip ip;

      public: // API exposed to Rust
        // Access regmap content
        uint32_t read_reg(uint64_t addr) const;
        void write_reg(uint64_t addr, uint32_t value);
        // Handle onboard memory
        std::unique_ptr<MemZone> alloc(MemZonePropertiesCxx props);

    };

    // Utility function to properly instantiate Cxx class in rust world
    std::unique_ptr<HpuHw>
      new_hpu_hw(uint32_t fpga_id, rust::String kernel_name, rust::String awsxclbin,
          VerbosityCxx verbose);
}

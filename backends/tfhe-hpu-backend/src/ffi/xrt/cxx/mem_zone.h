#pragma once
#include "rust/cxx.h"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <memory>
#include <optional>
#include <queue>



// XRT includes
#include "experimental/xrt_bo.h"
#include "experimental/xrt_ip.h"
#include "experimental/xrt_device.h"
#include "experimental/xrt_xclbin.h"

// Some Arch related defined
#define MEM_BANK_SIZE_MiB 512
#define MEM_CHUNK_SIZE ((size_t)(16*1024*1024))

namespace ffi {
    // Forward definition: Concrete implementation is made by Cxx
    enum class SyncModeCxx: uint8_t;

    class MemZone {
      public:
        MemZone(size_t size_b, size_t hbm_pc, xrt::bo* bo);
        ~MemZone();

      private:
        const size_t size_b;
        const size_t hbm_pc;
        xrt::bo* bo;
        std::optional<uint64_t*> map;

      public: // API exposed to Rust
        uint64_t paddr() const;
        uint64_t size() const ;
        uint64_t pc() const ;
        void read_bytes(size_t ofst, rust::Slice<uint8_t> bytes) const;
        void write_bytes(size_t ofst, rust::Slice<const uint8_t> bytes);
        void sync(SyncModeCxx mode);
        rust::Slice<uint64_t> mmap();
        void unmap();
    };

}

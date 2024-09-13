#include "tfhe-hpu-backend/src/ffi/xrt/cxx/mem_zone.h"
#include "tfhe-hpu-backend/src/ffi/xrt/mod.rs.h"

#include <iostream>

namespace ffi {

  MemZone::MemZone(size_t size_b, size_t hbm_pc, xrt::bo* bo)
  : size_b(size_b), hbm_pc(hbm_pc), bo(bo), map{}
  {}

  MemZone::~MemZone(){
    delete bo;
  }

  uint64_t MemZone::paddr() const {
    return bo->address();
    
  }
  size_t MemZone::size() const {
    return bo->size();
  }
  size_t MemZone::pc() const {
    return hbm_pc;
  }

  void MemZone::read_bytes(size_t ofst, rust::Slice<uint8_t> bytes) const {
    bo->read(bytes.data(), bytes.size()*sizeof(uint8_t), ofst);
  }

  void MemZone::write_bytes(size_t ofst, rust::Slice<const uint8_t> bytes){
    bo->write(bytes.data(), bytes.size()*sizeof(uint8_t), ofst);
  }

  void MemZone::sync(SyncModeCxx mode){
      switch (mode) {
        case SyncModeCxx::Host2Device:
          bo->sync(XCL_BO_SYNC_BO_TO_DEVICE);
          break;
        case SyncModeCxx::Device2Host:
          bo->sync(XCL_BO_SYNC_BO_FROM_DEVICE);
          break;
      }
      return;
  }

  rust::Slice<uint64_t> MemZone::mmap(){
    if (!map.has_value()) {
      map = bo->map<uint64_t*>();
    }
      return rust::Slice<uint64_t>{map.value(), size_b/sizeof(uint64_t)};
  }

  void MemZone::unmap(){
    if (map.has_value()) {
      delete map.value();
    }
  }
}

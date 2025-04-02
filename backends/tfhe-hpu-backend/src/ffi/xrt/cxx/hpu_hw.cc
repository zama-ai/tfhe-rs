#include "tfhe-hpu-backend/src/ffi/xrt/cxx/hpu_hw.h"
#include "tfhe-hpu-backend/src/ffi/xrt/mod.rs.h"

#include <iostream>

namespace ffi {

    HpuHw::HpuHw(uint32_t fpga_id, rust::String _kernel_name, rust::String _xclbin_name, VerbosityCxx verbose)
      : fpga_id{fpga_id}, kernel_name{std::string(_kernel_name)}, xclbin_name{std::string(_xclbin_name)}, verbose(verbose)
    {
      pr_info(verbose, "Create HwHpu Cxx type\n")
      pr_info(verbose, "Open the fpga: " << fpga_id << "\n")
      fpga = xrt::device(fpga_id);
      pr_info(verbose, "Load the xclbin " << xclbin_name << "\n");
      auto uuid = fpga.load_xclbin(xclbin_name);
      auto xclbin = xrt::xclbin(xclbin_name);

      // Get CU endpoints --------------------------------------------------------
      pr_info(verbose, "Fetch  Compute Units endpoints " << kernel_name << "\n")

      ip = xrt::ip(fpga, uuid, kernel_name.c_str());
      std::vector<xrt::xclbin::ip> cu;

      for (auto& kernel : xclbin.get_kernels()) {
        if (kernel.get_name() == kernel_name.c_str()) {
          cu = kernel.get_cus();
          break;
        }
      }
      if (cu.empty())
        throw std::runtime_error("IP not found in the provided xclbin");
     
      // Display kernel and memory information -----------------------------------
      if (verbose >= VerbosityCxx::Trace) {
        std::cout << kernel_name << " CU properties: " << std::endl;
        for (auto& cu_i: cu) {
          std::cout << "instance name:  " << cu_i.get_name() << "\n";
          std::cout << "base address:   0x" << std::hex << cu_i.get_base_address() << std::dec << "\n";
          for (const auto& arg : cu_i.get_args()) {
            std::cout << "  argument:       " << arg.get_name() << "\n";
            std::cout << "  hosttype:       " << arg.get_host_type() << "\n";
            std::cout << "  port:           " << arg.get_port() << "\n";
            std::cout << "  size (bytes):   0x" << std::hex << arg.get_size() << std::dec << "\n";
            std::cout << "  offset:         0x" << std::hex << arg.get_offset() << std::dec << "\n";
            for (const auto& mem : arg.get_mems()) {
              std::cout << "mem tag:        " << mem.get_tag() << "\n";
              std::cout << "mem index:      " << mem.get_index() << "\n";
              std::cout << "mem size (kb):  0x" << std::hex << mem.get_size_kb() << std::dec << "\n";
              std::cout << "mem base addr:  0x" << std::hex << mem.get_base_address() << std::dec << "\n";
            }
          }
          std::cout << std::endl;
        }
      }

      if (verbose >= VerbosityCxx::Debug) {
        std::cout << "Display memory layout:\n";
        for (auto& mem : xclbin.get_mems()) {
          std::cout << "mem tag:        " << mem.get_tag() << "\n";
          std::cout << "mem used:       " << (mem.get_used() ? "true" : "false") << "\n";
          std::cout << "mem index:      " << mem.get_index() << "\n";
          std::cout << "mem size (kb):  0x" << std::hex << mem.get_size_kb() << std::dec << "\n";
          std::cout << "mem base addr:  0x" << std::hex << mem.get_base_address() << std::dec << "\n";
        }
      }
    }

    HpuHw::~HpuHw()
    {
      pr_info(verbose, "Delete HwHpu Cxx type\n")
    }

    // Access regmap content
    uint32_t HpuHw::read_reg(uint64_t addr) const
    {
      auto reg_val = ip.read_register(addr);
      pr_trace(verbose, "read_reg:: @0x" <<std::hex<< addr << " => 0x" << reg_val <<"\n")
      return reg_val;
    }

    void HpuHw::write_reg(uint64_t addr, uint32_t value)
    {
      pr_trace(verbose, "write_reg:: @0x" <<std::hex<< addr << " => 0x" << value <<"\n")
      return ip.write_register(addr, value);
    }

    // Handle onboard memory
    std::unique_ptr<MemZone> HpuHw::alloc(MemZonePropertiesCxx props){
      // NB: Currently XRT buffer are limited to 16MiB.
      // if bigger buffer are required, user must split them in chunks and check that allocated
      // chunk remains contiguous in memory (cf paddr)
      assert((props.size_b <= MEM_CHUNK_SIZE_B) && "MemZone couldn't be bigger than 16MiB.");

      auto bo = new xrt::bo(fpga, props.size_b, props.hbm_pc);
      return std::make_unique<MemZone>(props.size_b, props.hbm_pc, bo);
    }

    std::unique_ptr<HpuHw>
      new_hpu_hw(uint32_t fpga_id, rust::String kernel_name, rust::String awsxclbin,
        VerbosityCxx verbose)
      {
        return std::make_unique<HpuHw>(fpga_id, kernel_name, awsxclbin, verbose);
      }
}

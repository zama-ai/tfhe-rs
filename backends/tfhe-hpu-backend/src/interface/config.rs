//! Define Hpu configuration
//! Provide mechanism to load it from Toml-file

use std::collections::HashMap;

/// Configuration of targeted FFI bridge witht the Hw
/// Enable to select targeted ffi interface with specific properties
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub enum FFIMode {
    Xrt {
        id: u32,
        kernel: String,
        xclbin: String,
    },
    Sim {
        ipc_name: String,
    },
}

/// Configuration of targeted Fpga
/// Define Bitstream and kernel properties
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FpgaConfig {
    pub regmap: String,
    pub polling_us: u64,
    pub ffi: FFIMode,
}

/// Configuration of Rtl
/// Rtl has some internal knobs that could be configured
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RtlConfig {
    /// Select pe-pbs configuration Ipip or Bpip
    pub bpip_used: bool,
    /// Timeout value to start Bpip even if batch isn't full
    pub bpip_timeout: u32,
}

/// On-board memory configuration
/// Define the Hbm pc properties and required memory size
/// NB: Hbm pc must match with `fpga/xr/kernel/${board}/cfg/${config}.cfg`
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct BoardConfig {
    /// Ciphertext memory
    /// Expressed the number of ciphertext slot to allocate
    pub ct_mem: usize,
    /// Depict the list of hbm_pc connected to ct master_axi
    pub ct_pc: Vec<usize>,
    /// Expressed the number of ct_mem slot used for heap
    /// Heap is then used downward
    pub heap_size: usize,

    /// Expressed the number of PbsLut slot to allocate
    pub lut_mem: usize,
    /// Depict the hbm_pc connected to glwe master_axi
    pub lut_pc: usize,

    /// Expressed the size in u32 word allocated to Fw table
    pub fw_size: usize,
    /// Depict the hbm_pc connected to ucore fw master_axi
    pub fw_pc: usize,

    /// Depict the hbm_pc connected to bsk master_axi
    pub bsk_pc: Vec<usize>,
    /// Depict the hbm_pc connected to bsk master_axi
    pub ksk_pc: Vec<usize>,
}

/// Embedded Fw properties
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FwConfig {
    pub sim: String,
    pub kogge: String,

    /// List of supported integer width
    /// NB: Currently only one width is supported at a time
    pub integer_w: Vec<usize>,

    /// List of custom iop to load
    /// IopName -> Iop asm file
    pub custom_iop: HashMap<String, String>,

    // Whether to target fw for ipip or not
    pub ipip: bool
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct HpuConfig {
    pub fpga: FpgaConfig,
    pub rtl: RtlConfig,
    pub board: BoardConfig,
    pub firmware: FwConfig,
}

impl HpuConfig {
    pub fn read_from(file: &str) -> Self {
        let file_str = match std::fs::read_to_string(file) {
            Ok(str) => str,
            Err(err) => {
                panic!("Error: `{file}`:: {err}");
            }
        };

        match toml::from_str(&file_str) {
            Ok(cfg) => cfg,
            Err(err) => panic!("Error: {err}"),
        }
    }
}

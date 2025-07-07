//! Define Hpu configuration
//! Provide mechanism to load it from Toml-file

use crate::ffi;
use crate::fw::rtl::config::RtlCfg;
use std::collections::{HashMap, HashSet};

/// ShellString
/// Thin wrapper around String that provide a method to interpolate it's content with environment
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ShellString(String);
impl ShellString {
    pub fn new(from: String) -> Self {
        Self(from)
    }
    pub fn expand(&self) -> String {
        // Regex that match on $MY_VAR or ${MY_VAR}
        let shell_regex = regex::Regex::new(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?").unwrap();

        // Replace each bash var occurrence with the associated environment variable value
        let cow = shell_regex.replace_all(&self.0, |caps: &regex::Captures| {
            let shell_var = &caps[1];
            std::env::var(shell_var).unwrap_or_else(|_| {
                panic!("Error: ShellString used env_var <{shell_var}> not found")
            })
        });
        cow.to_string()
    }
}

/// Custom FromStr implementation to enable usage with clap CLI
impl std::str::FromStr for ShellString {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

/// Configuration of targeted FFI bridge with the Hw
/// Enable to select targeted ffi interface with specific properties
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub enum FFIMode {
    V80 {
        id: ShellString,
        board_sn: ShellString,
        hpu_path: ShellString,
        ami_path: ShellString,
        qdma_h2c: ShellString,
        qdma_c2h: ShellString,
    },
    Xrt {
        id: u32,
        kernel: ShellString,
        xclbin: ShellString,
    },
    Sim {
        ipc_name: ShellString,
    },
}

/// Configuration of targeted Fpga
/// Define Bitstream and kernel properties
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FpgaConfig {
    pub regmap: Vec<ShellString>,
    pub polling_us: u64,
    pub ffi: FFIMode,
}

/// Configuration of Rtl
/// Rtl has some internal knobs that could be configured
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RtlConfig {
    /// Select pe-pbs configuration Ipip or Bpip
    pub bpip_use: bool,
    /// When Bpip is used, select to use opportunistic behavior
    pub bpip_use_opportunism: bool,
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
    /// Depict the list of memories connected to ct master_axi
    pub ct_pc: Vec<ffi::MemKind>,
    /// Expressed the number of ct_mem slot used for heap
    /// Heap is then used downward
    pub heap_size: usize,

    /// Expressed the number of PbsLut slot to allocate
    pub lut_mem: usize,
    /// Depict the memory connected to glwe master_axi
    pub lut_pc: ffi::MemKind,

    /// Expressed the size in u32 word allocated to Fw table
    pub fw_size: usize,
    /// Depict the memory connected to ucore fw master_axi
    pub fw_pc: ffi::MemKind,
    /// Depict the memory connected to trace manager
    pub trace_pc: ffi::MemKind,
    /// The trace memory depth in MB
    pub trace_depth: usize,

    /// Depict the hbm_pc connected to bsk master_axi
    pub bsk_pc: Vec<ffi::MemKind>,
    /// Depict the hbm_pc connected to bsk master_axi
    pub ksk_pc: Vec<ffi::MemKind>,
}

/// Embedded Fw properties
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FwConfig {
    /// List of supported integer width
    /// NB: Currently only one width is supported at a time
    pub integer_w: HashSet<usize>,

    /// Kogge config filename
    /// Used to depicts best tradeoff for kogge Add/Sub algorithm
    pub kogge_cfg: ShellString,

    /// List of custom iop to load
    /// IopName -> Iop asm file
    pub custom_iop: HashMap<String, ShellString>,

    /// A per IOP configuration
    pub op_cfg: RtlCfg,

    /// Defines the firmware implementation to use
    pub implementation: String,

    /// Defines the minimum batch size for an accurate FW simulation (use this
    /// while this information is not available as a register in the hardware)
    pub min_batch_size: usize,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct HpuConfig {
    pub fpga: FpgaConfig,
    pub rtl: RtlConfig,
    pub board: BoardConfig,
    pub firmware: FwConfig,
}

impl HpuConfig {
    /// Provide Serde mechanisms from TOML file
    pub fn from_toml(file: &str) -> Self {
        let file_str = match std::fs::read_to_string(file) {
            Ok(str) => str,
            Err(err) => {
                panic!("Error: `{file}`:: {err}");
            }
        };

        match toml::from_str(&file_str) {
            Ok(cfg) => cfg,
            Err(err) => panic!("Toml error in `{file}`: {err}"),
        }
    }
}

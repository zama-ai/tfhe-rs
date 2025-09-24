//! Contains definition of Hpu architecture related parameters
//! Those parameters are architecture dependents and have direct impact over memory order
//! They are required to correctly arrange entities data in an Hpu usable order.

#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum HpuNoiseDistributionInput {
    GaussianStdDev(f64),
    TUniformBound(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum HpuModulusSwitchType {
    Standard,
    CenteredMeanNoiseReduction,
}

/// Parameters related to Tfhe scheme computation
/// Couldn't rely on ClassicPBSParameters to prevent dependency loop
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HpuPBSParameters {
    pub lwe_dimension: usize,
    pub glwe_dimension: usize,
    pub polynomial_size: usize,
    pub lwe_noise_distribution: HpuNoiseDistributionInput,
    pub glwe_noise_distribution: HpuNoiseDistributionInput,
    pub pbs_base_log: usize,
    pub pbs_level: usize,
    pub ks_base_log: usize,
    pub ks_level: usize,
    pub message_width: usize,
    pub carry_width: usize,
    pub ciphertext_width: usize,
    pub log2_p_fail: f64,
    pub modulus_switch_type: HpuModulusSwitchType,
}

// Manual implementation of Eq trait
// Indeed, we can handle strict comparison of f64
impl std::cmp::Eq for HpuPBSParameters {}

impl HpuPBSParameters {
    /// Compute associated encoding delta.
    /// Used for scalar encoding
    pub fn delta(&self) -> u64 {
        1_u64
            << (self.ciphertext_width
                - (self.message_width + self.carry_width + /* padding_bit */ 1))
    }
}

/// Parameters related to Keyswitch computation
/// Related to architectural implementation of Ks in Hpu
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HpuKeyswitchParameters {
    /// Bit width
    pub width: usize,
    /// Parallelism over X
    pub lbx: usize,
    /// Parallelism over Y
    pub lby: usize,
    /// Parallelism over Z
    pub lbz: usize,
}

/// Parameters related to NTT computation
/// Related to architectural implementation of NTT/INTT in Hpu
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HpuNttParameters {
    /// Core architecture
    pub core_arch: HpuNttCoreArch,
    /// Minimum #PBS in the batch for full throughput
    pub min_pbs_nb: Option<usize>,
    /// #PBS in Ntt Pipe
    pub batch_pbs_nb: usize,
    /// Maximum #PBS store in Pep
    pub total_pbs_nb: usize,

    /// Bit width of ciphertext modulus (pow2 modulus)
    pub ct_width: u32,

    /// Radix value. Must be a power of 2
    pub radix: usize,
    /// Stages number -> Total number of stages. Note that R^S = N the number of coefficients of
    /// the NTT.
    pub stg_nb: usize,
    // Prime used during computation
    pub prime_modulus: HpuNttPrime,

    /// Psi value -> Number of radix blocks that work in parallel
    pub psi: usize,
    /// Delta value -> Number of stages before pcg network
    pub delta: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HpuNttCoreArch {
    WmmCompactPcg,
    WmmUnfoldPcg,
    GF64(Vec<u8>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HpuNttPrime {
    GF64 = 0,
    Solinas3_32_17_13 = 1,
    Solinas2_44_14 = 2,
}
impl From<&HpuNttPrime> for u64 {
    fn from(prime: &HpuNttPrime) -> Self {
        match prime {
            HpuNttPrime::GF64 => {
                /* Goldilocks64 */
                ((1_u128 << 64) - (1_u128 << 32) + 1_u128) as u64
            }
            HpuNttPrime::Solinas3_32_17_13 => {
                /* Solinas3_32_17_13 */
                ((1_u128 << 32) - (1_u128 << 17) - (1_u128 << 13) + 1) as u64
            }
            HpuNttPrime::Solinas2_44_14 => {
                /* Solinas2_44_14 */
                ((1_u128 << 44) - (1_u128 << 14) + 1) as u64
            }
        }
    }
}

impl HpuNttParameters {
    pub fn stg_iter(&self, poly_n: usize) -> usize {
        poly_n / (self.radix * self.psi)
    }

    pub fn ls_delta(&self) -> usize {
        if 0 == (self.stg_nb % self.delta) {
            self.delta - 1
        } else {
            (self.stg_nb % self.delta) - 1
        }
    }
}

/// Parameters related to Hbm PC
/// Related to memory connection and allocated channel
/// Only specify the number of Pc allocated to each interface.
/// The concrete mapping of pc on memory channel is defined by the user in the top-level
/// configuration file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HpuPcParameters {
    pub ksk_pc: usize,
    pub ksk_bytes_w: usize,
    pub bsk_pc: usize,
    pub glwe_pc: usize, // Currently hardcoded to 1
    pub bsk_bytes_w: usize,
    pub pem_pc: usize,
    pub pem_bytes_w: usize,
    pub glwe_bytes_w: usize,
}

/// Parameters related to regfile
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HpuRegfileParameters {
    /// Number of register
    pub reg_nb: usize,
    /// Number of coefs in  // at the regfile boundary
    pub coef_nb: usize,
}

/// Parameters related to Instruction Scheduler
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HpuIscParameters {
    /// HPU lookahead buffer depth
    /// Number of instruction that are considered in advance
    pub depth: usize,

    /// Minimum Number of DOps per IOp
    pub min_iop_size: usize,
}

/// HpuArchitecturesParameters
/// Describe Architecture constants that have direct import on memory shuffling and slicing
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HpuParameters {
    pub pbs_params: HpuPBSParameters,
    pub ntt_params: HpuNttParameters,
    pub ks_params: HpuKeyswitchParameters,
    pub pc_params: HpuPcParameters,
    pub regf_params: HpuRegfileParameters,
    pub isc_params: HpuIscParameters,
}

/// Provide Serde mechanisms in ron file
impl HpuParameters {
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

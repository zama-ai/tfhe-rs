//! HpuHw mockup ffi interface
use super::*;
use crate::ffi;
use hw_regmap::FlatRegmap;

use crate::interface::rtl::params::*;

pub struct HpuHw {
    regmap: FlatRegmap,
    params: ffi::HpuParameters,
}

impl HpuHw {
    /// Get register name from addr
    fn get_register_name(&self, addr: u64) -> &str {
        let register = self
            .regmap
            .register()
            .iter()
            .find(|(_name, reg)| *reg.offset() == (addr as usize))
            .expect("Register addr not found in registermap");

        register.0
    }
}

impl HpuHw {
    pub fn read_reg(&self, addr: u64) -> u32 {
        let register_name = self.get_register_name(addr);
        match register_name {
            "Info::NttInternal" => {
                let ntt_p = &self.params.ntt_params;
                (ntt_p.radix + (ntt_p.psi << 8) /*+(ntt_p.div << 16)*/ + (ntt_p.delta << 24)) as u32
            }
            "Info::NttArch" => match self.params.ntt_params.core_arch {
                crate::entities::HpuNttCoreArch::WmmCompact => NTT_CORE_ARCH_OFS + 0,
                crate::entities::HpuNttCoreArch::WmmPipeline => NTT_CORE_ARCH_OFS + 1,
                crate::entities::HpuNttCoreArch::WmmUnfold => NTT_CORE_ARCH_OFS + 2,
                crate::entities::HpuNttCoreArch::WmmCompactPcg => NTT_CORE_ARCH_OFS + 3,
                crate::entities::HpuNttCoreArch::WmmUnfoldPcg => NTT_CORE_ARCH_OFS + 4,
                crate::entities::HpuNttCoreArch::GF64(_) => NTT_CORE_ARCH_OFS + 5,
            },
            "Info::NttPbsNb" => {
                let ntt_p = &self.params.ntt_params;
                (ntt_p.batch_pbs_nb + (ntt_p.total_pbs_nb << 8)) as u32
            }
            "Info::NttModulo" => {
                const GF64: u64 = ((1_u128 << 64) - (1_u128 << 32) + 1_u128) as u64;
                const SOLINAS3_32_17_13: u64 =
                    ((1_u128 << 32) - (1_u128 << 17) - (1_u128 << 13)) as u64;
                const SOLINAS2_44_14: u64 = ((1_u128 << 44) - (1_u128 << 14) + 1) as u64;

                match self.params.ntt_params.prime_modulus {
                    GF64 => MOD_NTT_NAME_OFS + 0,
                    SOLINAS3_32_17_13 => MOD_NTT_NAME_OFS + 1,
                    SOLINAS2_44_14 => MOD_NTT_NAME_OFS + 2,
                    _ => panic!("Unknown NttModPrime"),
                }
            }

            "Info::Appli" => {
                if CONCRETE_BOOLEAN == self.params.pbs_params {
                    APPLICATION_NAME_OFS + 0
                } else if MSG2_CARRY2 == self.params.pbs_params {
                    APPLICATION_NAME_OFS + 1
                } else if MSG2_CARRY2_64B == self.params.pbs_params {
                    APPLICATION_NAME_OFS + 3
                } else if MSG2_CARRY2_44B == self.params.pbs_params {
                    APPLICATION_NAME_OFS + 4
                } else if MSG2_CARRY2_64B_FAKE == self.params.pbs_params {
                    APPLICATION_NAME_OFS + 9
                } else {
                    panic!("Unsupported reverse PBS_PARAMS lookup")
                }
            }
            "Info::KsShape" => {
                let ks_p = &self.params.ks_params;
                (ks_p.lbx + (ks_p.lby << 8) + (ks_p.lbz << 16)) as u32
            }
            "Info::KsInfo" => {
                let ks_p = &self.params.ks_params;
                let pbs_p = &self.params.pbs_params;
                (ks_p.width + (pbs_p.ks_level << 8) + (pbs_p.ks_base_log << 16)) as u32
            }
            "Info::HbmPc" => {
                let pc_p = &self.params.pc_params;
                // TODO: Cut number currently not reverted
                (pc_p.bsk_pc + (pc_p.ksk_pc << 16)) as u32
            }
            "Info::HbmPc_2" => {
                let pc_p = &self.params.pc_params;
                pc_p.pem_pc as u32
            }
            "Info::RegfInfo" => {
                let regf_p = &self.params.regf_params;
                (regf_p.reg_nb + (regf_p.coef_nb << 8)) as u32
            }
            "Info::IscInfo" => {
                let isc_p = &self.params.isc_params;
                isc_p.min_iop_size as u32
            }

            _ => {
                tracing::warn!("Register {register_name} not hooked for reading, return 0");
                0
            }
        }
    }

    pub fn write_reg(&mut self, addr: u64, value: u32) {
        let register_name = self.get_register_name(addr);
        match register_name {
            _ => tracing::debug!("Register {register_name} not hooked for writting"),
        }
    }

    pub fn alloc(&mut self, props: ffi::MemZoneProperties) -> MemZone {
        todo!()
    }

    pub fn release(&mut self, zone: &MemZone) {}

    /// Handle ffi instanciation
    #[inline(always)]
    pub fn new_hpu_hw(config: ffi::FpgaConfig) -> HpuHw {
        // Check config
        let params = match config.ffi {
            ffi::FFIMode::Sim(params) => params,
            _ => panic!("Unsupported config type with ffi::sim"),
        };
        let regmap = FlatRegmap::from_file(&config.regmap);
        Self { regmap, params }
    }
}

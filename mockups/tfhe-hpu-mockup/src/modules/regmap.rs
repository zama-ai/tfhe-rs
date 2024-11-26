use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use hw_regmap::FlatRegmap;
use tfhe::tfhe_hpu_backend::interface::rtl::params::*;
use tfhe::tfhe_hpu_backend::prelude::*;

#[derive(Default)]
pub(crate) struct KeyState {
    avail: AtomicBool,
    rst_pdg: AtomicBool,
}
impl KeyState {
    pub fn is_avail(&self) -> bool {
        self.avail.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
pub(crate) struct BpipState {
    pub(crate) used: bool,
    pub(crate) timeout: u32,
}

#[derive(Default)]
pub(crate) struct AddrOffset {
    pub(crate) bsk: [(u32, u32); hbm::HBM_BSK_PC_MAX],
    pub(crate) ksk: [(u32, u32); hbm::HBM_KSK_PC_MAX],
    pub(crate) lut: (u32, u32),
    pub(crate) ldst: [(u32, u32); hbm::HBM_CT_PC_MAX],
}

pub struct RegisterMap {
    rtl_params: HpuParameters,
    regmap: FlatRegmap,

    bsk: KeyState,
    ksk: KeyState,
    bpip: BpipState,
    addr_ofst: AddrOffset,
    ackq_pdg: VecDeque<u32>,
}

pub enum RegisterEvent {
    None,
    KeyReset,
    WorkQ(u32),
}

impl RegisterMap {
    pub fn new(rtl_params: HpuParameters, regmap: &str) -> Self {
        let regmap = FlatRegmap::from_file(regmap);
        Self {
            rtl_params,
            regmap,
            bsk: Default::default(),
            ksk: Default::default(),
            bpip: Default::default(),
            addr_ofst: Default::default(),
            ackq_pdg: VecDeque::new(),
        }
    }

    pub fn bsk_state(&self) -> &KeyState {
        &self.bsk
    }
    pub fn ksk_state(&self) -> &KeyState {
        &self.ksk
    }
    pub fn bpip_state(&self) -> &BpipState {
        &self.bpip
    }
    pub fn addr_offset(&self) -> &AddrOffset {
        &self.addr_ofst
    }

    pub fn ack_pdg(&mut self, ack: u32) {
        self.ackq_pdg.push_back(ack)
    }
}

/// Implement revert register access
/// -> Emulate Rtl response of register read/write
impl RegisterMap {
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

    /// Kind of register reverse
    /// Return register value from parameter value
    pub fn read_reg(&mut self, addr: u64) -> u32 {
        let register_name = self.get_register_name(addr);
        match register_name {
            "Info::NttInternal" => {
                let ntt_p = &self.rtl_params.ntt_params;
                (ntt_p.radix + (ntt_p.psi << 8) /*+(ntt_p.div << 16)*/ + (ntt_p.delta << 24)) as u32
            }
            "Info::NttRdxCut" => {
                let ntt_p = &self.rtl_params.ntt_params;
                let cut_w = match &ntt_p.core_arch {
                    HpuNttCoreArch::GF64(cut_w) => cut_w,
                    _ => &vec![ntt_p.delta as u8],
                };
                cut_w
                    .iter()
                    .enumerate()
                    .fold(0, |acc, (id, val)| acc + ((*val as u32) << (id * 4)))
            }
            "Info::NttArch" => match self.rtl_params.ntt_params.core_arch {
                HpuNttCoreArch::WmmCompact => NTT_CORE_ARCH_OFS,
                HpuNttCoreArch::WmmPipeline => NTT_CORE_ARCH_OFS + 1,
                HpuNttCoreArch::WmmUnfold => NTT_CORE_ARCH_OFS + 2,
                HpuNttCoreArch::WmmCompactPcg => NTT_CORE_ARCH_OFS + 3,
                HpuNttCoreArch::WmmUnfoldPcg => NTT_CORE_ARCH_OFS + 4,
                HpuNttCoreArch::GF64(_) => NTT_CORE_ARCH_OFS + 5,
            },
            "Info::NttPbsNb" => {
                let ntt_p = &self.rtl_params.ntt_params;
                (ntt_p.batch_pbs_nb + (ntt_p.total_pbs_nb << 8)) as u32
            }
            "Info::NttModulo" => {
                const GF64: u64 = ((1_u128 << 64) - (1_u128 << 32) + 1_u128) as u64;
                const SOLINAS3_32_17_13: u64 =
                    ((1_u128 << 32) - (1_u128 << 17) - (1_u128 << 13)) as u64;
                const SOLINAS2_44_14: u64 = ((1_u128 << 44) - (1_u128 << 14) + 1) as u64;

                match self.rtl_params.ntt_params.prime_modulus {
                    GF64 => MOD_NTT_NAME_OFS,
                    SOLINAS3_32_17_13 => MOD_NTT_NAME_OFS + 1,
                    SOLINAS2_44_14 => MOD_NTT_NAME_OFS + 2,
                    _ => panic!("Unknown NttModPrime"),
                }
            }

            "Info::Appli" => {
                if CONCRETE_BOOLEAN == self.rtl_params.pbs_params {
                    APPLICATION_NAME_OFS
                } else if MSG2_CARRY2 == self.rtl_params.pbs_params {
                    APPLICATION_NAME_OFS + 1
                } else if MSG2_CARRY2_64B == self.rtl_params.pbs_params {
                    APPLICATION_NAME_OFS + 3
                } else if MSG2_CARRY2_44B == self.rtl_params.pbs_params {
                    APPLICATION_NAME_OFS + 4
                } else if MSG2_CARRY2_64B_FAKE == self.rtl_params.pbs_params {
                    APPLICATION_NAME_OFS + 9
                } else {
                    // Custom simulation parameters set
                    // -> Return 1 without NAME_OFS
                    1
                }
            }
            "Info::KsShape" => {
                let ks_p = &self.rtl_params.ks_params;
                (ks_p.lbx + (ks_p.lby << 8) + (ks_p.lbz << 16)) as u32
            }
            "Info::KsInfo" => {
                let ks_p = &self.rtl_params.ks_params;
                let pbs_p = &self.rtl_params.pbs_params;
                (ks_p.width + (pbs_p.ks_level << 8) + (pbs_p.ks_base_log << 16)) as u32
            }
            "Info::HbmPc" => {
                let pc_p = &self.rtl_params.pc_params;
                // TODO: Cut number currently not reverted
                (pc_p.bsk_pc + (pc_p.ksk_pc << 16)) as u32
            }
            "Info::HbmPc_2" => {
                let pc_p = &self.rtl_params.pc_params;
                pc_p.pem_pc as u32
            }
            "Info::ksk_axi4_data_w" => {
                let bytes_w = &self.rtl_params.pc_params.ksk_bytes_w;
                *bytes_w as u32 * u8::BITS
            }
            "Info::bsk_axi4_data_w" => {
                let bytes_w = &self.rtl_params.pc_params.bsk_bytes_w;
                *bytes_w as u32 * u8::BITS
            }
            "Info::pem_axi4_data_w" => {
                let bytes_w = &self.rtl_params.pc_params.pem_bytes_w;
                *bytes_w as u32 * u8::BITS
            }
            "Info::glwe_axi4_data_w" => {
                let bytes_w = &self.rtl_params.pc_params.glwe_bytes_w;
                *bytes_w as u32 * u8::BITS
            }

            "Info::RegfInfo" => {
                let regf_p = &self.rtl_params.regf_params;
                (regf_p.reg_nb + (regf_p.coef_nb << 8)) as u32
            }
            "Info::IscInfo" => {
                let isc_p = &self.rtl_params.isc_params;
                isc_p.min_iop_size as u32
            }

            "Keys_Bsk::avail" => self.bsk.avail.load(Ordering::SeqCst) as u32,
            "Keys_Bsk::reset" => {
                if self.bsk.rst_pdg.load(Ordering::SeqCst) {
                    self.bsk.rst_pdg.store(false, Ordering::SeqCst);
                    1 << 31
                } else {
                    0
                }
            }
            "Keys_Ksk::avail" => self.ksk.avail.load(Ordering::SeqCst) as u32,
            "Keys_Ksk::reset" => {
                if self.ksk.rst_pdg.load(Ordering::SeqCst) {
                    self.ksk.rst_pdg.store(false, Ordering::SeqCst);
                    1 << 31
                } else {
                    0
                }
            }

            // Bpip configuration registers
            "Bpip::use" => self.bpip.used as u32,
            "Bpip::timeout" => self.bpip.timeout,

            // Add offset configuration registers
            "LdSt::addr_pc0_msb" => self.addr_ofst.ldst[0].0,
            "LdSt::addr_pc0_lsb" => self.addr_ofst.ldst[0].1,
            "LdSt::addr_pc1_msb" => self.addr_ofst.ldst[1].0,
            "LdSt::addr_pc1_lsb" => self.addr_ofst.ldst[1].1,
            "Keys_Bsk::addr_pc_pc0_msb" => self.addr_ofst.bsk[0].0,
            "Keys_Bsk::addr_pc_pc0_lsb" => self.addr_ofst.bsk[0].1,
            "Keys_Bsk::addr_pc_pc1_msb" => self.addr_ofst.bsk[1].0,
            "Keys_Bsk::addr_pc_pc1_lsb" => self.addr_ofst.bsk[1].1,
            "Keys_Bsk::addr_pc_pc2_msb" => self.addr_ofst.bsk[2].0,
            "Keys_Bsk::addr_pc_pc2_lsb" => self.addr_ofst.bsk[2].1,
            "Keys_Bsk::addr_pc_pc3_msb" => self.addr_ofst.bsk[3].0,
            "Keys_Bsk::addr_pc_pc3_lsb" => self.addr_ofst.bsk[3].1,
            "Keys_Bsk::addr_pc_pc4_msb" => self.addr_ofst.bsk[4].0,
            "Keys_Bsk::addr_pc_pc4_lsb" => self.addr_ofst.bsk[4].1,
            "Keys_Bsk::addr_pc_pc5_msb" => self.addr_ofst.bsk[5].0,
            "Keys_Bsk::addr_pc_pc5_lsb" => self.addr_ofst.bsk[5].1,
            "Keys_Bsk::addr_pc_pc6_msb" => self.addr_ofst.bsk[6].0,
            "Keys_Bsk::addr_pc_pc6_lsb" => self.addr_ofst.bsk[6].1,
            "Keys_Bsk::addr_pc_pc7_msb" => self.addr_ofst.bsk[7].0,
            "Keys_Bsk::addr_pc_pc7_lsb" => self.addr_ofst.bsk[7].1,
            "Keys_Ksk::addr_pc_pc0_msb" => self.addr_ofst.ksk[0].0,
            "Keys_Ksk::addr_pc_pc0_lsb" => self.addr_ofst.ksk[0].1,
            "Keys_Ksk::addr_pc_pc1_msb" => self.addr_ofst.ksk[1].0,
            "Keys_Ksk::addr_pc_pc1_lsb" => self.addr_ofst.ksk[1].1,
            "Keys_Ksk::addr_pc_pc2_msb" => self.addr_ofst.ksk[2].0,
            "Keys_Ksk::addr_pc_pc2_lsb" => self.addr_ofst.ksk[2].1,
            "Keys_Ksk::addr_pc_pc3_msb" => self.addr_ofst.ksk[3].0,
            "Keys_Ksk::addr_pc_pc3_lsb" => self.addr_ofst.ksk[3].1,
            "Keys_Ksk::addr_pc_pc4_msb" => self.addr_ofst.ksk[4].0,
            "Keys_Ksk::addr_pc_pc4_lsb" => self.addr_ofst.ksk[4].1,
            "Keys_Ksk::addr_pc_pc5_msb" => self.addr_ofst.ksk[5].0,
            "Keys_Ksk::addr_pc_pc5_lsb" => self.addr_ofst.ksk[5].1,
            "Keys_Ksk::addr_pc_pc6_msb" => self.addr_ofst.ksk[6].0,
            "Keys_Ksk::addr_pc_pc6_lsb" => self.addr_ofst.ksk[6].1,
            "Keys_Ksk::addr_pc_pc7_msb" => self.addr_ofst.ksk[7].0,
            "Keys_Ksk::addr_pc_pc7_lsb" => self.addr_ofst.ksk[7].1,
            "PbsLut::addr_msb" => self.addr_ofst.lut.0,
            "PbsLut::addr_lsb" => self.addr_ofst.lut.1,

            // Queue interface
            "WorkAck::workq" => {
                // TODO implement finite size queue
                0
            }
            "WorkAck::ackq" => {
                if let Some(ack) = self.ackq_pdg.pop_front() {
                    ack
                } else {
                    ACKQ_EMPTY
                }
            }

            _ => {
                tracing::warn!("Register {register_name} not hooked for reading, return 0");
                0
            }
        }
    }

    pub fn write_reg(&mut self, addr: u64, value: u32) -> RegisterEvent {
        let register_name = self.get_register_name(addr);
        match register_name {
            "Keys_Bsk::avail" => {
                self.bsk.avail.store((value & 0x1) == 0x1, Ordering::SeqCst);
                RegisterEvent::None
            }
            "Keys_Bsk::reset" => {
                if (value & 0x1) == 0x1 {
                    self.bsk.rst_pdg.store(true, Ordering::SeqCst);
                    self.bsk.avail.store(false, Ordering::SeqCst);
                    RegisterEvent::KeyReset
                } else {
                    RegisterEvent::None
                }
            }
            "Keys_Ksk::avail" => {
                self.ksk.avail.store((value & 0x1) == 0x1, Ordering::SeqCst);
                RegisterEvent::None
            }
            "Keys_Ksk::reset" => {
                if (value & 0x1) == 0x1 {
                    self.ksk.rst_pdg.store(true, Ordering::SeqCst);
                    self.ksk.avail.store(false, Ordering::SeqCst);
                    RegisterEvent::KeyReset
                } else {
                    RegisterEvent::None
                }
            }

            // Bpip configuration registers
            "Bpip::use" => {
                self.bpip.used = value == 0x1;
                RegisterEvent::None
            }
            "Bpip::timeout" => {
                self.bpip.timeout = value;
                RegisterEvent::None
            }
            // Add offset configuration registers
            "LdSt::addr_pc0_msb" => {
                self.addr_ofst.ldst[0].0 = value;
                RegisterEvent::None
            }
            "LdSt::addr_pc0_lsb" => {
                self.addr_ofst.ldst[0].1 = value;
                RegisterEvent::None
            }
            "LdSt::addr_pc1_msb" => {
                self.addr_ofst.ldst[1].0 = value;
                RegisterEvent::None
            }
            "LdSt::addr_pc1_lsb" => {
                self.addr_ofst.ldst[1].1 = value;
                RegisterEvent::None
            }
            "Keys_Bsk::addr_pc_pc0_msb" => {
                self.addr_ofst.bsk[0].0 = value;
                RegisterEvent::None
            }
            "Keys_Bsk::addr_pc_pc0_lsb" => {
                self.addr_ofst.bsk[0].1 = value;
                RegisterEvent::None
            }
            "Keys_Bsk::addr_pc_pc1_msb" => {
                self.addr_ofst.bsk[1].0 = value;
                RegisterEvent::None
            }
            "Keys_Bsk::addr_pc_pc1_lsb" => {
                self.addr_ofst.bsk[1].1 = value;
                RegisterEvent::None
            }
            "Keys_Bsk::addr_pc_pc2_msb" => {
                self.addr_ofst.bsk[2].0 = value;
                RegisterEvent::None
            }
            "Keys_Bsk::addr_pc_pc2_lsb" => {
                self.addr_ofst.bsk[2].1 = value;
                RegisterEvent::None
            }
            "Keys_Bsk::addr_pc_pc3_msb" => {
                self.addr_ofst.bsk[3].0 = value;
                RegisterEvent::None
            }
            "Keys_Bsk::addr_pc_pc3_lsb" => {
                self.addr_ofst.bsk[3].1 = value;
                RegisterEvent::None
            }
            "Keys_Bsk::addr_pc_pc4_msb" => {
                self.addr_ofst.bsk[4].0 = value;
                RegisterEvent::None
            }
            "Keys_Bsk::addr_pc_pc4_lsb" => {
                self.addr_ofst.bsk[4].1 = value;
                RegisterEvent::None
            }
            "Keys_Bsk::addr_pc_pc5_msb" => {
                self.addr_ofst.bsk[5].0 = value;
                RegisterEvent::None
            }
            "Keys_Bsk::addr_pc_pc5_lsb" => {
                self.addr_ofst.bsk[5].1 = value;
                RegisterEvent::None
            }
            "Keys_Bsk::addr_pc_pc6_msb" => {
                self.addr_ofst.bsk[6].0 = value;
                RegisterEvent::None
            }
            "Keys_Bsk::addr_pc_pc6_lsb" => {
                self.addr_ofst.bsk[6].1 = value;
                RegisterEvent::None
            }
            "Keys_Bsk::addr_pc_pc7_msb" => {
                self.addr_ofst.bsk[7].0 = value;
                RegisterEvent::None
            }
            "Keys_Bsk::addr_pc_pc7_lsb" => {
                self.addr_ofst.bsk[7].1 = value;
                RegisterEvent::None
            }
            "Keys_Ksk::addr_pc_pc0_msb" => {
                self.addr_ofst.ksk[0].0 = value;
                RegisterEvent::None
            }
            "Keys_Ksk::addr_pc_pc0_lsb" => {
                self.addr_ofst.ksk[0].1 = value;
                RegisterEvent::None
            }
            "Keys_Ksk::addr_pc_pc1_msb" => {
                self.addr_ofst.ksk[1].0 = value;
                RegisterEvent::None
            }
            "Keys_Ksk::addr_pc_pc1_lsb" => {
                self.addr_ofst.ksk[1].1 = value;
                RegisterEvent::None
            }
            "Keys_Ksk::addr_pc_pc2_msb" => {
                self.addr_ofst.ksk[2].0 = value;
                RegisterEvent::None
            }
            "Keys_Ksk::addr_pc_pc2_lsb" => {
                self.addr_ofst.ksk[2].1 = value;
                RegisterEvent::None
            }
            "Keys_Ksk::addr_pc_pc3_msb" => {
                self.addr_ofst.ksk[3].0 = value;
                RegisterEvent::None
            }
            "Keys_Ksk::addr_pc_pc3_lsb" => {
                self.addr_ofst.ksk[3].1 = value;
                RegisterEvent::None
            }
            "Keys_Ksk::addr_pc_pc4_msb" => {
                self.addr_ofst.ksk[4].0 = value;
                RegisterEvent::None
            }
            "Keys_Ksk::addr_pc_pc4_lsb" => {
                self.addr_ofst.ksk[4].1 = value;
                RegisterEvent::None
            }
            "Keys_Ksk::addr_pc_pc5_msb" => {
                self.addr_ofst.ksk[5].0 = value;
                RegisterEvent::None
            }
            "Keys_Ksk::addr_pc_pc5_lsb" => {
                self.addr_ofst.ksk[5].1 = value;
                RegisterEvent::None
            }
            "Keys_Ksk::addr_pc_pc6_msb" => {
                self.addr_ofst.ksk[6].0 = value;
                RegisterEvent::None
            }
            "Keys_Ksk::addr_pc_pc6_lsb" => {
                self.addr_ofst.ksk[6].1 = value;
                RegisterEvent::None
            }
            "Keys_Ksk::addr_pc_pc7_msb" => {
                self.addr_ofst.ksk[7].0 = value;
                RegisterEvent::None
            }
            "Keys_Ksk::addr_pc_pc7_lsb" => {
                self.addr_ofst.ksk[7].1 = value;
                RegisterEvent::None
            }
            "PbsLut::addr_msb" => {
                self.addr_ofst.lut.0 = value;
                RegisterEvent::None
            }
            "PbsLut::addr_lsb" => {
                self.addr_ofst.lut.1 = value;
                RegisterEvent::None
            }

            "WorkAck::workq" => RegisterEvent::WorkQ(value),
            _ => {
                tracing::warn!("Register {register_name} not hooked for writting");
                RegisterEvent::None
            }
        }
    }
}

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use hpu_regmap::FlatRegmap;
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
    pub(crate) use_opportunism: bool,
    pub(crate) timeout: u32,
}

#[derive(Default)]
pub(crate) struct AddrOffset {
    pub(crate) bsk: [(u32, u32); memory::hbm::HBM_BSK_PC_MAX],
    pub(crate) ksk: [(u32, u32); memory::hbm::HBM_KSK_PC_MAX],
    pub(crate) lut: (u32, u32),
    pub(crate) ldst: [(u32, u32); memory::MEM_CT_PC_MAX],
    pub(crate) trace: (u32, u32),
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
    pub fn new(rtl_params: HpuParameters, regmap: &[&str]) -> Self {
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
            "info::ntt_structure" => {
                let ntt_p = &self.rtl_params.ntt_params;
                (ntt_p.radix + (ntt_p.psi << 8) /*+(ntt_p.div << 16)*/ + (ntt_p.delta << 24)) as u32
            }
            "info::ntt_rdx_cut" => {
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
            "info::ntt_architecture" => match self.rtl_params.ntt_params.core_arch {
                HpuNttCoreArch::WmmCompact => NTT_CORE_ARCH_OFS,
                HpuNttCoreArch::WmmPipeline => NTT_CORE_ARCH_OFS + 1,
                HpuNttCoreArch::WmmUnfold => NTT_CORE_ARCH_OFS + 2,
                HpuNttCoreArch::WmmCompactPcg => NTT_CORE_ARCH_OFS + 3,
                HpuNttCoreArch::WmmUnfoldPcg => NTT_CORE_ARCH_OFS + 4,
                HpuNttCoreArch::GF64(_) => NTT_CORE_ARCH_OFS + 5,
            },
            "info::ntt_pbs" => {
                let ntt_p = &self.rtl_params.ntt_params;
                (ntt_p.batch_pbs_nb + (ntt_p.total_pbs_nb << 8)) as u32
            }
            "info::ntt_modulo" => {
                MOD_NTT_NAME_OFS + (self.rtl_params.ntt_params.prime_modulus.clone() as u8) as u32
            }

            "info::application" => {
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
                } else if MSG2_CARRY2_GAUSSIAN == self.rtl_params.pbs_params {
                    APPLICATION_NAME_OFS + 10
                } else if MSG2_CARRY2_TUNIFORM == self.rtl_params.pbs_params {
                    APPLICATION_NAME_OFS + 11
                } else if MSG2_CARRY2_PFAIL64_132B_GAUSSIAN_1F72DBA == self.rtl_params.pbs_params {
                    APPLICATION_NAME_OFS + 12
                } else {
                    // Custom simulation parameters set
                    // -> Return 1 without NAME_OFS
                    1
                }
            }
            "info::ks_structure" => {
                let ks_p = &self.rtl_params.ks_params;
                (ks_p.lbx + (ks_p.lby << 8) + (ks_p.lbz << 16)) as u32
            }
            "info::ks_crypto_param" => {
                let ks_p = &self.rtl_params.ks_params;
                let pbs_p = &self.rtl_params.pbs_params;
                (ks_p.width + (pbs_p.ks_level << 8) + (pbs_p.ks_base_log << 16)) as u32
            }
            "info::hbm_axi4_nb" => {
                let pc_p = &self.rtl_params.pc_params;
                // TODO: Cut number currently not reverted
                (pc_p.bsk_pc + (pc_p.ksk_pc << 8) + (pc_p.pem_pc << 16)) as u32
            }
            "info::hbm_axi4_dataw_ksk" => {
                let bytes_w = &self.rtl_params.pc_params.ksk_bytes_w;
                *bytes_w as u32 * u8::BITS
            }
            "info::hbm_axi4_dataw_bsk" => {
                let bytes_w = &self.rtl_params.pc_params.bsk_bytes_w;
                *bytes_w as u32 * u8::BITS
            }
            "info::hbm_axi4_dataw_pem" => {
                let bytes_w = &self.rtl_params.pc_params.pem_bytes_w;
                *bytes_w as u32 * u8::BITS
            }
            "info::hbm_axi4_dataw_glwe" => {
                let bytes_w = &self.rtl_params.pc_params.glwe_bytes_w;
                *bytes_w as u32 * u8::BITS
            }

            "info::regf_structure" => {
                let regf_p = &self.rtl_params.regf_params;
                (regf_p.reg_nb + (regf_p.coef_nb << 8)) as u32
            }
            "info::isc_structure" => {
                let isc_p = &self.rtl_params.isc_params;
                (isc_p.depth + (isc_p.min_iop_size << 8)) as u32
            }

            "bsk_avail::avail" => self.bsk.avail.load(Ordering::SeqCst) as u32,
            "bsk_avail::reset" => {
                if self.bsk.rst_pdg.load(Ordering::SeqCst) {
                    self.bsk.rst_pdg.store(false, Ordering::SeqCst);
                    1 << 31
                } else {
                    0
                }
            }
            "ksk_avail::avail" => self.ksk.avail.load(Ordering::SeqCst) as u32,
            "ksk_avail::reset" => {
                if self.ksk.rst_pdg.load(Ordering::SeqCst) {
                    self.ksk.rst_pdg.store(false, Ordering::SeqCst);
                    1 << 31
                } else {
                    0
                }
            }

            // Bpip configuration registers
            "bpip::use" => ((self.bpip.used as u8) + ((self.bpip.use_opportunism as u8) << 1))as u32,
            "bpip::timeout" => self.bpip.timeout,

            // Add offset configuration registers
            "hbm_axi4_addr_1in3::ct_pc0_msb" => self.addr_ofst.ldst[0].0,
            "hbm_axi4_addr_1in3::ct_pc0_lsb" => self.addr_ofst.ldst[0].1,
            "hbm_axi4_addr_1in3::ct_pc1_msb" => self.addr_ofst.ldst[1].0,
            "hbm_axi4_addr_1in3::ct_pc1_lsb" => self.addr_ofst.ldst[1].1,
            "hbm_axi4_addr_3in3::bsk_pc0_msb" => self.addr_ofst.bsk[0].0,
            "hbm_axi4_addr_3in3::bsk_pc0_lsb" => self.addr_ofst.bsk[0].1,
            "hbm_axi4_addr_3in3::bsk_pc1_msb" => self.addr_ofst.bsk[1].0,
            "hbm_axi4_addr_3in3::bsk_pc1_lsb" => self.addr_ofst.bsk[1].1,
            "hbm_axi4_addr_3in3::bsk_pc2_msb" => self.addr_ofst.bsk[2].0,
            "hbm_axi4_addr_3in3::bsk_pc2_lsb" => self.addr_ofst.bsk[2].1,
            "hbm_axi4_addr_3in3::bsk_pc3_msb" => self.addr_ofst.bsk[3].0,
            "hbm_axi4_addr_3in3::bsk_pc3_lsb" => self.addr_ofst.bsk[3].1,
            "hbm_axi4_addr_3in3::bsk_pc4_msb" => self.addr_ofst.bsk[4].0,
            "hbm_axi4_addr_3in3::bsk_pc4_lsb" => self.addr_ofst.bsk[4].1,
            "hbm_axi4_addr_3in3::bsk_pc5_msb" => self.addr_ofst.bsk[5].0,
            "hbm_axi4_addr_3in3::bsk_pc5_lsb" => self.addr_ofst.bsk[5].1,
            "hbm_axi4_addr_3in3::bsk_pc6_msb" => self.addr_ofst.bsk[6].0,
            "hbm_axi4_addr_3in3::bsk_pc6_lsb" => self.addr_ofst.bsk[6].1,
            "hbm_axi4_addr_3in3::bsk_pc7_msb" => self.addr_ofst.bsk[7].0,
            "hbm_axi4_addr_3in3::bsk_pc7_lsb" => self.addr_ofst.bsk[7].1,
            "hbm_axi4_addr_3in3::bsk_pc8_msb" => self.addr_ofst.bsk[8].0,
            "hbm_axi4_addr_3in3::bsk_pc8_lsb" => self.addr_ofst.bsk[8].1,
            "hbm_axi4_addr_3in3::bsk_pc9_msb" => self.addr_ofst.bsk[9].0,
            "hbm_axi4_addr_3in3::bsk_pc9_lsb" => self.addr_ofst.bsk[9].1,
            "hbm_axi4_addr_3in3::bsk_pc10_msb" => self.addr_ofst.bsk[10].0,
            "hbm_axi4_addr_3in3::bsk_pc10_lsb" => self.addr_ofst.bsk[10].1,
            "hbm_axi4_addr_3in3::bsk_pc11_msb" => self.addr_ofst.bsk[11].0,
            "hbm_axi4_addr_3in3::bsk_pc11_lsb" => self.addr_ofst.bsk[11].1,
            "hbm_axi4_addr_3in3::bsk_pc12_msb" => self.addr_ofst.bsk[12].0,
            "hbm_axi4_addr_3in3::bsk_pc12_lsb" => self.addr_ofst.bsk[12].1,
            "hbm_axi4_addr_3in3::bsk_pc13_msb" => self.addr_ofst.bsk[13].0,
            "hbm_axi4_addr_3in3::bsk_pc13_lsb" => self.addr_ofst.bsk[13].1,
            "hbm_axi4_addr_3in3::bsk_pc14_msb" => self.addr_ofst.bsk[14].0,
            "hbm_axi4_addr_3in3::bsk_pc14_lsb" => self.addr_ofst.bsk[14].1,
            "hbm_axi4_addr_3in3::bsk_pc15_msb" => self.addr_ofst.bsk[15].0,
            "hbm_axi4_addr_3in3::bsk_pc15_lsb" => self.addr_ofst.bsk[15].1,
            "hbm_axi4_addr_1in3::ksk_pc0_msb" => self.addr_ofst.ksk[0].0,
            "hbm_axi4_addr_1in3::ksk_pc0_lsb" => self.addr_ofst.ksk[0].1,
            "hbm_axi4_addr_1in3::ksk_pc1_msb" => self.addr_ofst.ksk[1].0,
            "hbm_axi4_addr_1in3::ksk_pc1_lsb" => self.addr_ofst.ksk[1].1,
            "hbm_axi4_addr_1in3::ksk_pc2_msb" => self.addr_ofst.ksk[2].0,
            "hbm_axi4_addr_1in3::ksk_pc2_lsb" => self.addr_ofst.ksk[2].1,
            "hbm_axi4_addr_1in3::ksk_pc3_msb" => self.addr_ofst.ksk[3].0,
            "hbm_axi4_addr_1in3::ksk_pc3_lsb" => self.addr_ofst.ksk[3].1,
            "hbm_axi4_addr_1in3::ksk_pc4_msb" => self.addr_ofst.ksk[4].0,
            "hbm_axi4_addr_1in3::ksk_pc4_lsb" => self.addr_ofst.ksk[4].1,
            "hbm_axi4_addr_1in3::ksk_pc5_msb" => self.addr_ofst.ksk[5].0,
            "hbm_axi4_addr_1in3::ksk_pc5_lsb" => self.addr_ofst.ksk[5].1,
            "hbm_axi4_addr_1in3::ksk_pc6_msb" => self.addr_ofst.ksk[6].0,
            "hbm_axi4_addr_1in3::ksk_pc6_lsb" => self.addr_ofst.ksk[6].1,
            "hbm_axi4_addr_1in3::ksk_pc7_msb" => self.addr_ofst.ksk[7].0,
            "hbm_axi4_addr_1in3::ksk_pc7_lsb" => self.addr_ofst.ksk[7].1,
            "hbm_axi4_addr_1in3::ksk_pc8_msb" => self.addr_ofst.ksk[8].0,
            "hbm_axi4_addr_1in3::ksk_pc8_lsb" => self.addr_ofst.ksk[8].1,
            "hbm_axi4_addr_1in3::ksk_pc9_msb" => self.addr_ofst.ksk[9].0,
            "hbm_axi4_addr_1in3::ksk_pc9_lsb" => self.addr_ofst.ksk[9].1,
            "hbm_axi4_addr_1in3::ksk_pc10_msb" => self.addr_ofst.ksk[10].0,
            "hbm_axi4_addr_1in3::ksk_pc10_lsb" => self.addr_ofst.ksk[10].1,
            "hbm_axi4_addr_1in3::ksk_pc11_msb" => self.addr_ofst.ksk[11].0,
            "hbm_axi4_addr_1in3::ksk_pc11_lsb" => self.addr_ofst.ksk[11].1,
            "hbm_axi4_addr_1in3::ksk_pc12_msb" => self.addr_ofst.ksk[12].0,
            "hbm_axi4_addr_1in3::ksk_pc12_lsb" => self.addr_ofst.ksk[12].1,
            "hbm_axi4_addr_1in3::ksk_pc13_msb" => self.addr_ofst.ksk[13].0,
            "hbm_axi4_addr_1in3::ksk_pc13_lsb" => self.addr_ofst.ksk[13].1,
            "hbm_axi4_addr_1in3::ksk_pc14_msb" => self.addr_ofst.ksk[14].0,
            "hbm_axi4_addr_1in3::ksk_pc14_lsb" => self.addr_ofst.ksk[14].1,
            "hbm_axi4_addr_1in3::ksk_pc15_msb" => self.addr_ofst.ksk[15].0,
            "hbm_axi4_addr_1in3::ksk_pc15_lsb" => self.addr_ofst.ksk[15].1,
            "hbm_axi4_addr_1in3::glwe_pc0_msb" => self.addr_ofst.lut.0,
            "hbm_axi4_addr_1in3::glwe_pc0_lsb" => self.addr_ofst.lut.1,
            "hbm_axi4_addr_1in3::trc_pc0_msb" => self.addr_ofst.trace.0,
            "hbm_axi4_addr_1in3::trc_pc0_lsb" => self.addr_ofst.trace.1,

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
            "bsk_avail::avail" => {
                self.bsk.avail.store((value & 0x1) == 0x1, Ordering::SeqCst);
                RegisterEvent::None
            }
            "bsk_avail::reset" => {
                if (value & 0x1) == 0x1 {
                    self.bsk.rst_pdg.store(true, Ordering::SeqCst);
                    self.bsk.avail.store(false, Ordering::SeqCst);
                    RegisterEvent::KeyReset
                } else {
                    RegisterEvent::None
                }
            }
            "ksk_avail::avail" => {
                self.ksk.avail.store((value & 0x1) == 0x1, Ordering::SeqCst);
                RegisterEvent::None
            }
            "ksk_avail::reset" => {
                if (value & 0x1) == 0x1 {
                    self.ksk.rst_pdg.store(true, Ordering::SeqCst);
                    self.ksk.avail.store(false, Ordering::SeqCst);
                    RegisterEvent::KeyReset
                } else {
                    RegisterEvent::None
                }
            }

            // Bpip configuration registers
            "bpip::use" => {
                self.bpip.used = (value & 0x1) == 0x1;
                self.bpip.use_opportunism = (value & 0x2) == 0x2;
                RegisterEvent::None
            }
            "bpip::timeout" => {
                self.bpip.timeout = value;
                RegisterEvent::None
            }
            // Add offset configuration registers
            "hbm_axi4_addr_1in3::ct_pc0_msb" => {
                self.addr_ofst.ldst[0].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ct_pc0_lsb" => {
                self.addr_ofst.ldst[0].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ct_pc1_msb" => {
                self.addr_ofst.ldst[1].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ct_pc1_lsb" => {
                self.addr_ofst.ldst[1].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc0_msb" => {
                self.addr_ofst.bsk[0].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc0_lsb" => {
                self.addr_ofst.bsk[0].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc1_msb" => {
                self.addr_ofst.bsk[1].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc1_lsb" => {
                self.addr_ofst.bsk[1].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc2_msb" => {
                self.addr_ofst.bsk[2].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc2_lsb" => {
                self.addr_ofst.bsk[2].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc3_msb" => {
                self.addr_ofst.bsk[3].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc3_lsb" => {
                self.addr_ofst.bsk[3].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc4_msb" => {
                self.addr_ofst.bsk[4].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc4_lsb" => {
                self.addr_ofst.bsk[4].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc5_msb" => {
                self.addr_ofst.bsk[5].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc5_lsb" => {
                self.addr_ofst.bsk[5].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc6_msb" => {
                self.addr_ofst.bsk[6].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc6_lsb" => {
                self.addr_ofst.bsk[6].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc7_msb" => {
                self.addr_ofst.bsk[7].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc7_lsb" => {
                self.addr_ofst.bsk[7].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc8_msb" => {
                self.addr_ofst.bsk[8].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc8_lsb" => {
                self.addr_ofst.bsk[8].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc9_msb" => {
                self.addr_ofst.bsk[9].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc9_lsb" => {
                self.addr_ofst.bsk[9].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc10_msb" => {
                self.addr_ofst.bsk[10].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc10_lsb" => {
                self.addr_ofst.bsk[10].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc11_msb" => {
                self.addr_ofst.bsk[11].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc11_lsb" => {
                self.addr_ofst.bsk[11].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc12_msb" => {
                self.addr_ofst.bsk[12].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc12_lsb" => {
                self.addr_ofst.bsk[12].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc13_msb" => {
                self.addr_ofst.bsk[13].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc13_lsb" => {
                self.addr_ofst.bsk[13].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc14_msb" => {
                self.addr_ofst.bsk[14].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc14_lsb" => {
                self.addr_ofst.bsk[14].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc15_msb" => {
                self.addr_ofst.bsk[15].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_3in3::bsk_pc15_lsb" => {
                self.addr_ofst.bsk[15].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc0_msb" => {
                self.addr_ofst.ksk[0].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc0_lsb" => {
                self.addr_ofst.ksk[0].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc1_msb" => {
                self.addr_ofst.ksk[1].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc1_lsb" => {
                self.addr_ofst.ksk[1].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc2_msb" => {
                self.addr_ofst.ksk[2].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc2_lsb" => {
                self.addr_ofst.ksk[2].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc3_msb" => {
                self.addr_ofst.ksk[3].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc3_lsb" => {
                self.addr_ofst.ksk[3].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc4_msb" => {
                self.addr_ofst.ksk[4].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc4_lsb" => {
                self.addr_ofst.ksk[4].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc5_msb" => {
                self.addr_ofst.ksk[5].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc5_lsb" => {
                self.addr_ofst.ksk[5].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc6_msb" => {
                self.addr_ofst.ksk[6].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc6_lsb" => {
                self.addr_ofst.ksk[6].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc7_msb" => {
                self.addr_ofst.ksk[7].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc7_lsb" => {
                self.addr_ofst.ksk[7].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc8_msb" => {
                self.addr_ofst.ksk[8].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc8_lsb" => {
                self.addr_ofst.ksk[8].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc9_msb" => {
                self.addr_ofst.ksk[9].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc9_lsb" => {
                self.addr_ofst.ksk[9].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc10_msb" => {
                self.addr_ofst.ksk[10].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc10_lsb" => {
                self.addr_ofst.ksk[10].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc11_msb" => {
                self.addr_ofst.ksk[11].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc11_lsb" => {
                self.addr_ofst.ksk[11].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc12_msb" => {
                self.addr_ofst.ksk[12].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc12_lsb" => {
                self.addr_ofst.ksk[12].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc13_msb" => {
                self.addr_ofst.ksk[13].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc13_lsb" => {
                self.addr_ofst.ksk[13].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc14_msb" => {
                self.addr_ofst.ksk[14].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc14_lsb" => {
                self.addr_ofst.ksk[14].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc15_msb" => {
                self.addr_ofst.ksk[15].0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::ksk_pc15_lsb" => {
                self.addr_ofst.ksk[15].1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::glwe_pc0_msb" => {
                self.addr_ofst.lut.0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::glwe_pc0_lsb" => {
                self.addr_ofst.lut.1 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::trc_pc0_msb" => {
                self.addr_ofst.trace.0 = value;
                RegisterEvent::None
            }
            "hbm_axi4_addr_1in3::trc_pc0_lsb" => {
                self.addr_ofst.trace.1 = value;
                RegisterEvent::None
            }

            "WorkAck::workq" => RegisterEvent::WorkQ(value),
            _ => {
                tracing::warn!("Register {register_name} not hooked for writing");
                RegisterEvent::None
            }
        }
    }
}

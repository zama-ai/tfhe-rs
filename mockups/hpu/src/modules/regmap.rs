use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

use hw_regmap::FlatRegmap;
use tfhe::tfhe_hpu_backend::interface::rtl::params::*;
use tfhe::tfhe_hpu_backend::prelude::*;

#[derive(Default)]
struct KeyState {
    avail: AtomicBool,
    rst_pdg: AtomicBool,
}

pub struct RegisterMap {
    rtl_params: HpuParameters,
    regmap: FlatRegmap,
    bsk: KeyState,
    ksk: KeyState,

    workq_tx: mpsc::Sender<u32>,
    ackq_rx: mpsc::Receiver<u32>,
}

pub enum RegisterEvent {
    None,
    KeyReset,
}

impl RegisterMap {
    pub fn new(
        rtl_params: HpuParameters,
        regmap: &str,
    ) -> (Self, (mpsc::Receiver<u32>, mpsc::Sender<u32>)) {
        let regmap = FlatRegmap::from_file(&regmap);
        let (workq_tx, workq_rx) = mpsc::channel();
        let (ackq_tx, ackq_rx) = mpsc::channel();

        (
            Self {
                rtl_params,
                regmap,
                bsk: Default::default(),
                ksk: Default::default(),
                workq_tx,
                ackq_rx,
            },
            (workq_rx, ackq_tx),
        )
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
            "Info::NttArch" => match self.rtl_params.ntt_params.core_arch {
                HpuNttCoreArch::WmmCompact => NTT_CORE_ARCH_OFS + 0,
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
                    GF64 => MOD_NTT_NAME_OFS + 0,
                    SOLINAS3_32_17_13 => MOD_NTT_NAME_OFS + 1,
                    SOLINAS2_44_14 => MOD_NTT_NAME_OFS + 2,
                    _ => panic!("Unknown NttModPrime"),
                }
            }

            "Info::Appli" => {
                if CONCRETE_BOOLEAN == self.rtl_params.pbs_params {
                    APPLICATION_NAME_OFS + 0
                } else if MSG2_CARRY2 == self.rtl_params.pbs_params {
                    APPLICATION_NAME_OFS + 1
                } else if MSG2_CARRY2_64B == self.rtl_params.pbs_params {
                    APPLICATION_NAME_OFS + 3
                } else if MSG2_CARRY2_44B == self.rtl_params.pbs_params {
                    APPLICATION_NAME_OFS + 4
                } else if MSG2_CARRY2_64B_FAKE == self.rtl_params.pbs_params {
                    APPLICATION_NAME_OFS + 9
                } else {
                    panic!(
                        "Unsupported reverse PBS_PARAMS lookup {:?}",
                        self.rtl_params.pbs_params
                    )
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

            // Queue interface
            "WorkAck::workq" => {
                // TODO implement finite size queue
                0
            }
            "WorkAck::ackq" => match self.ackq_rx.try_recv() {
                Ok(ack) => ack,
                Err(mpsc::TryRecvError::Empty) => ACKQ_EMPTY,
                Err(mpsc::TryRecvError::Disconnected) => panic!("HpuSim inner channel closed"),
            },

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
            "WorkAck::workq" => {
                self.workq_tx.send(value).unwrap();
                RegisterEvent::None
            }
            _ => {
                tracing::warn!("Register {register_name} not hooked for writting");
                RegisterEvent::None
            }
        }
    }
}

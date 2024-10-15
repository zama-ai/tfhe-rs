use std::array::from_fn;

use hw_regmap::FlatRegmap;

mod ipc;
use ipc::Ipc;

mod mockup_params;
pub use mockup_params::MockupParameters;

mod modules;
use modules::{HbmBank, RegisterMap, HBM_BANK_NB};

use tfhe::tfhe_hpu_backend::prelude::*;

pub struct HpuSim {
    config: HpuConfig,
    params: MockupParameters,
    ipc: Ipc,
    regmap: RegisterMap,
    hbm_bank: [HbmBank; HBM_BANK_NB],
}

impl HpuSim {
    pub fn new(config: HpuConfig, params: MockupParameters) -> Self {
        // Allocate communication channels
        let ipc = {
            let name = match config.fpga.ffi {
                FFIMode::Sim { ref ipc_name } => ipc_name.to_string(),
                _ => panic!("Unsupported config type with ffi::sim"),
            };
            Ipc::new(&name)
        };

        // Allocate register map emulation
        let regmap = RegisterMap::new(params.rtl_params.clone(), &config.fpga.regmap);

        // Allocate on-board memory emulation
        let hbm_bank: [HbmBank; HBM_BANK_NB] = from_fn(|i| HbmBank::new(i));

        // // Allocate inner regfile and lock abstraction
        // let regfile = (0..params.isc_sim_params.register)
        //     .map(|_| T::default())
        //     .collect::<Vec<_>>();

        Self {
            config,
            params,
            ipc,
            regmap,
            hbm_bank,
        }
    }

    pub fn simulate(&mut self) {
        loop {
            // Flush register requests
            while let Some(req) = self.ipc.register_req() {
                match req {
                    RegisterReq::Read { addr } => {
                        let val = self.regmap.read_reg(addr);
                        self.ipc.register_ack(RegisterAck::Read(val));
                    }
                    RegisterReq::Write { addr, value } => {
                        self.regmap.write_reg(addr, value);
                        self.ipc.register_ack(RegisterAck::Write);
                    }
                }
            }

            // Flush memory requests
            while let Some(req) = self.ipc.memory_req() {
                match req {
                    MemoryReq::Allocate { hbm_pc, size_b } => {
                        let (addr, (tx, rx)) = self.hbm_bank[hbm_pc].alloc(size_b);
                        self.ipc.memory_ack(MemoryAck::Allocate { addr, tx, rx });
                    }
                    MemoryReq::Sync { hbm_pc, addr, mode } => {
                        // Triggered Sync event in the inner bank
                        // NB: Sync has no ack over Memory channel, instead rely on raw data ipc to
                        // synced
                        self.hbm_bank[hbm_pc].get_chunk(addr).sync(mode);
                    }
                    MemoryReq::Release { hbm_pc, addr } => {
                        self.hbm_bank[hbm_pc].rm_chunk(addr);
                        self.ipc.memory_ack(MemoryAck::Release);
                    }
                }
            }
        }
    }
}

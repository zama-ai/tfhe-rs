//! HpuHw mockup ffi interface
use crate::ffi::*;
use hw_regmap::FlatRegmap;

pub struct HpuHw {
    regmap: FlatRegmap,
    params: HpuParameters,
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
            _ => {
                tracing::debug!("Register {register_name} not hooked for reading, return 0");
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

    pub fn alloc(&mut self, props: MemZoneProperties) -> MemZone {
        todo!()
    }

    pub fn release(&mut self, zone: &MemZone) {}

    /// Handle ffi instanciation
    #[inline(always)]
    pub fn new_hpu_hw(config: FpgaConfig) -> HpuHw {
        // Check config
        let params = match config.ffi {
            FFIMode::Sim(params) => params,
            _ => panic!("Unsupported config type with ffi::sim"),
        };
        let regmap = FlatRegmap::from_file(&config.regmap);
        Self { regmap, params }
    }
}

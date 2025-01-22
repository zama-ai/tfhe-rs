use ron::de::from_reader;
use ron::ser::to_writer_pretty;
use std::fs::{File, OpenOptions};
use std::path::Path;

use crate::fw::isc_sim::pe::PeConfigStore;

/// Inner ucore parameters that wasn't exposed through rtl register
/// Use to modelized the performances of the isc
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[allow(non_snake_case)]
pub struct IscSimConfig {
    pub register: usize,
    pub isc_depth: usize,
    pub pe_cfg: String,
    pub freq_MHz: usize,
    pub quantum_us: usize,
}

/// Inner ucore parameters that wasn't exposed through rtl register
/// Use to modelized the performances of the isc
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[allow(non_snake_case)]
pub struct IscSimParameters {
    pub register: usize,
    pub isc_depth: usize,
    pub pe_cfg: PeConfigStore,
    pub freq_MHz: usize,
    pub quantum_us: usize,
}

/// Provide Serde mechanims in ron file
impl IscSimParameters {
    pub fn from_ron(params: &str) -> Self {
        let params_f =
            File::open(params).unwrap_or_else(|_| panic!("Failed opening file: {params}"));
        let sim_config: IscSimConfig = match from_reader(params_f) {
            Ok(data) => data,
            Err(err) => {
                panic!("Failed to load HpuParameters from file {}", err);
            }
        };
        IscSimParameters{
            register: sim_config.register,
            isc_depth: sim_config.isc_depth,
            pe_cfg: PeConfigStore::from_ron(&sim_config.pe_cfg),
            freq_MHz: sim_config.freq_MHz,
            quantum_us: sim_config.quantum_us
        }
    }

    pub fn to_ron(&self, params: &str) {
        let params_p = Path::new(params);
        if let Some(params_d) = params_p.parent() {
            std::fs::create_dir_all(params_d).unwrap();
        }

        let params_f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .append(false)
            .open(params_p)
            .unwrap();

        match to_writer_pretty(params_f, self, Default::default()) {
            Ok(_) => {}
            Err(err) => {
                panic!("Failed to write HpuParameters to file {}", err);
            }
        }
    }
}

impl Default for IscSimParameters {
    fn default() -> Self {
        // Make sure this is invalid
        IscSimParameters { 
            register: 0,
            isc_depth: 0,
            pe_cfg: PeConfigStore::default(),
            freq_MHz: 0,
            quantum_us: 0
        }
    }
}

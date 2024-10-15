use ron::de::from_reader;
use ron::ser::to_writer_pretty;
use std::fs::{File, OpenOptions};
use std::path::Path;

use tfhe::tfhe_hpu_backend::prelude::*;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MockupParameters {
    pub rtl_params: HpuParameters,
    pub isc_sim_params: IscSimParameters,
}

/// Inner ucore parameters that wasn't exposed through rtl register
/// Use to modelized the performances of the isc
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct IscSimParameters {
    pub register: usize,
    pub isc_depth: usize,
    pub alu_cfg: String,
    pub freq_MHz: usize,
}

// impl MockupParameters {
//     /// Compute number of digit blk based on integer_w and msg_w
//     pub fn blk_w(&self) -> usize {
//         self.integer_w.div_ceil(self.core_params.digit.msg_w)
//     }
// }

/// Provide Serde mechanims in ron file
impl MockupParameters {
    pub fn from_ron(params: &str) -> Self {
        let params_f = File::open(params).expect(&format!("Failed opening file: {params}"));
        match from_reader(params_f) {
            Ok(data) => data,
            Err(err) => {
                panic!("Failed to load HpuParameters from file {}", err);
            }
        }
    }

    pub fn to_ron(&self, params: &str) {
        let params_p = Path::new(params);
        if let Some(params_d) = params_p.parent() {
            std::fs::create_dir_all(params_d).unwrap();
        }

        let params_f = OpenOptions::new()
            .create(true)
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

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
#[allow(non_snake_case)]
pub struct IscSimParameters {
    pub register: usize,
    pub isc_depth: usize,
    pub pe_cfg: String,
    pub freq_MHz: usize,
    pub quantum_us: usize,
}

/// Provide Serde mechanims in ron file
impl MockupParameters {
    pub fn from_ron(params: &str) -> Self {
        let params_f =
            File::open(params).unwrap_or_else(|_| panic!("Failed opening file: {params}"));
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

/// Structure to pass runtime options
pub struct MockupOptions {
    pub dump_out: Option<String>,
    pub dump_reg: bool,
    pub report_out: Option<String>,
    pub report_trace: bool,
}

impl MockupOptions {
    fn create_dir(file_path: &str) {
        let path = Path::new(&file_path);
        if let Some(dir_p) = path.parent() {
            std::fs::create_dir_all(dir_p).unwrap();
        }
    }

    pub fn open_wr_file(file_path: &str) -> File {
        Self::create_dir(file_path);
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(file_path)
            .unwrap()
    }

    pub fn report_file(&self, iop: &hpu_asm::IOpName) -> Option<File> {
        if let Some(report_out) = &self.report_out {
            let iop_file = format!("{report_out}/{iop}.rpt");
            Some(Self::open_wr_file(&iop_file))
        } else {
            None
        }
    }
    pub fn report_trace(&self, iop: &hpu_asm::IOpName) -> Option<File> {
        if self.report_out.is_some() && self.report_trace {
            let report_out = &self.report_out.as_ref().unwrap();
            let iop_file = format!("{report_out}/{iop}.trace");
            Some(Self::open_wr_file(&iop_file))
        } else {
            None
        }
    }
}

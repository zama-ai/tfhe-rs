use ron::de::from_reader;
use std::fs::{File, OpenOptions};
use std::path::Path;

use tfhe::tfhe_hpu_backend::prelude::*;
use tfhe::tfhe_hpu_backend::fw::isc_sim::IscSimParameters;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MockupConfig {
    pub rtl_params: HpuParameters
}

#[derive(Clone, Debug)]
pub struct MockupParameters {
    pub rtl_params: HpuParameters,
    // isc_sim_params comes now from hpu_config
    pub isc_sim_params: IscSimParameters,
}

/// Provide Serde mechanims in ron file
impl MockupParameters {
    pub fn from_ron(params: &str) -> Self {
        let params_f =
            File::open(params).unwrap_or_else(|_| panic!("Failed opening file: {params}"));
        let rtl_params = match from_reader::<_, MockupConfig>(params_f) {
            Ok(data) => data,
            Err(err) => {
                panic!("Failed to load HpuParameters from file {}", err);
            }
        }.rtl_params;
        MockupParameters{rtl_params, isc_sim_params: IscSimParameters::default()}
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

    pub fn report_file(&self, iop: hpu_asm::AsmIOpcode) -> Option<File> {
        if let Some(report_out) = &self.report_out {
            let iop_file = format!("{report_out}/{iop}.rpt");
            Some(Self::open_wr_file(&iop_file))
        } else {
            None
        }
    }
    pub fn report_trace(&self, iop: hpu_asm::AsmIOpcode) -> Option<File> {
        if self.report_out.is_some() && self.report_trace {
            let report_out = &self.report_out.as_ref().unwrap();
            let iop_file = format!("{report_out}/{iop}.trace");
            Some(Self::open_wr_file(&iop_file))
        } else {
            None
        }
    }
}

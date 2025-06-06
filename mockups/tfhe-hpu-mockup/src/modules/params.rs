use std::fs::{File, OpenOptions};
use std::path::Path;

use tfhe::tfhe_hpu_backend::prelude::*;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MockupParameters {
    pub freq_mhz: usize,
    pub quantum_us: usize,
    pub rtl_params: HpuParameters,
}

/// Structure to pass runtime options
pub struct MockupOptions {
    pub dump_out: Option<String>,
    pub dump_reg: bool,
    pub report_out: Option<String>,
    pub report_trace: bool,
    pub trivial: bool,
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
            let iop_file = format!("{report_out}/{iop}.json");
            Some(Self::open_wr_file(&iop_file))
        } else {
            None
        }
    }
}

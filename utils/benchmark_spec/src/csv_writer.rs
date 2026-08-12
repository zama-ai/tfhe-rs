//! Appends benchmark results to a CSV file.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

pub struct CsvResultWriter {
    file: File,
}

impl CsvResultWriter {
    pub fn from_path(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("cannot create parent dirs");
            }
            File::create(path).expect("cannot create result file");
        }
        let file = OpenOptions::new()
            .append(true)
            .open(path)
            .expect("cannot open result file");
        Self { file }
    }

    pub fn write_result(&mut self, name: &str, value: usize) {
        writeln!(self.file, "{name},{value}")
            .unwrap_or_else(|err| panic!("cannot write {name} result into file: {err}"));
    }
}

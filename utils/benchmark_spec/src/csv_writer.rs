//! Appends benchmark results to a CSV file.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

pub struct CsvResultWriter {
    file: File,
}

impl CsvResultWriter {
    pub fn new(file_name: &str) -> Self {
        let file_path = Path::new(file_name);
        Self::from_path(file_path)
    }

    pub fn from_path(path: &Path) -> Self {
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
        let line = format!("{name},{value}\n");
        let error_message = format!("cannot write {name} result into file");
        self.file.write_all(line.as_bytes()).expect(&error_message);
    }
}

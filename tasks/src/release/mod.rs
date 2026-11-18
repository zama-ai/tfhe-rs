//! The release tooling: which crates need a version bump, a tag or a publication, and the
//! publication itself. See RELEASING.md.
//!
//! Everything is derived, nothing is hand-maintained: the crate list, versions and the dependency
//! graph come from `cargo metadata`, releases from the git tags, published versions from the index
//! of the registry, crates.io unless told otherwise.

use std::path::PathBuf;

use clap::Args;

mod plan;
mod publish;
mod registry;
mod repo;
mod status;

pub use publish::{ReleaseArgs, release};
pub use status::{StatusArgs, release_status};

use registry::Registry;
use repo::Repo;

/// Why a command stops, and the exit code it stops with.
#[derive(Debug)]
pub struct Failure {
    pub message: String,
    pub code: i32,
}

impl Failure {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: 1,
        }
    }

    /// The registry could not be asked, which says nothing about the crates.
    fn unreachable(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: 2,
        }
    }
}

impl<E: std::error::Error> From<E> for Failure {
    fn from(error: E) -> Self {
        Self::new(error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Failure>;

/// What is released, and where to.
#[derive(Args)]
pub struct Target {
    /// Repository to work on, defaults to the one holding this tool
    #[arg(long, value_name = "PATH")]
    repo: Option<PathBuf>,

    /// Registry the crates are released to, by the name cargo knows it by
    #[arg(long, value_name = "NAME", default_value = registry::CRATES_IO)]
    registry: String,

    /// Sparse index of --registry, required unless it is crates.io
    #[arg(long, value_name = "URL")]
    index: Option<String>,
}

impl Target {
    fn open(&self) -> Result<(Repo, Registry)> {
        let repo = Repo::new(self.repo.as_deref())?;
        let registry = Registry::new(&self.registry, self.index.as_deref())?;
        Ok((repo, registry))
    }
}

/// Print rows as left aligned columns, the first row being their header.
fn print_table(rows: &[Vec<String>]) {
    let widths: Vec<usize> = (0..rows[0].len())
        .map(|column| {
            let cells = rows.iter().map(|row| row[column].chars().count());
            cells.max().unwrap_or(0)
        })
        .collect();
    for row in rows {
        let cells: Vec<String> = row
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect();
        println!("{}", cells.join("  ").trim_end());
    }
}

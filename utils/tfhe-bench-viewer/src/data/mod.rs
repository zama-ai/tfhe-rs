//! What one fetch brought back, and what it can be written to.
//!
//! Nothing here re-implements the extractor: the ids are parsed by
//! `benchmark_spec`, and the query lives in [`fetch`].

// A page speaks HTTP, PostgreSQL speaks its own protocol over TCP, and a
// browser opens no TCP socket. The web build reads snapshots instead, and the
// stub is what says so.
#[cfg(not(target_arch = "wasm32"))]
mod fetch;
#[cfg(not(target_arch = "wasm32"))]
pub use fetch::Db;

#[cfg(target_arch = "wasm32")]
mod browser;
#[cfg(target_arch = "wasm32")]
pub use browser::Db;

use std::collections::{HashMap, HashSet};
use std::path::Path;

use benchmark_spec::{Backend, BenchmarkMetric};

use crate::catalogue::Node;

/// One stored result, reduced to what a plot reads.
///
/// Every field but `at` and `value` is a dimension the interface can filter on.
/// Two results differing on any of them belong to two different curves, so none
/// of these can be dropped without silently merging runs.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Point {
    /// Insertion time, in seconds since the epoch. The X axis.
    pub at: f64,
    pub value: f64,
    pub bits: i64,
    pub machine: String,
    pub params: String,
    /// Run flavour: `avx512`, or a string a workflow built.
    pub variant: String,
    /// `None` when the id did not parse. The value is still a value; it is the
    /// name that cannot be trusted to say what it measures.
    pub backend: Option<Backend>,
    pub metric: Option<BenchmarkMetric>,
}

/// What one fetch brought back: the paths that actually have results, and the
/// results themselves.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Store {
    /// The bench paths present in the data. Not the spec's full catalogue: a
    /// benchmark nobody ran in the window has nothing to plot, so it is not
    /// offered. Derived from the keys, so it is rebuilt rather than stored.
    #[serde(skip)]
    pub tree: Node,
    /// Keyed by rendered bench path for the ids that parsed, and by the whole
    /// stored name for those that did not.
    pub points: HashMap<String, Vec<Point>>,
    pub fetched: usize,
    /// The ids the current grammar does not parse, with what the parser said,
    /// one entry per distinct id. Kept whole rather than counted: this is the
    /// list of what the spec has yet to cover, and it is only actionable if it
    /// can be read.
    pub unparsed: Vec<(String, String)>,
    /// Rows behind those ids. Higher than `unparsed.len()`, since an id
    /// reappears on every machine and every run of the window.
    pub unparsed_rows: usize,
    pub days: i32,
}

impl Store {
    /// Every key but the ids that did not parse: those are stored names, not
    /// paths, and they have no place in a tree of paths.
    fn rebuild_tree(&mut self) {
        let unparsed: HashSet<&str> = self
            .unparsed
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();

        let mut tree = Node::root();
        for key in self.points.keys() {
            if !unparsed.contains(key.as_str()) {
                tree.insert(key);
            }
        }
        tree.sort();
        self.tree = tree;
    }

    pub fn paths(&self) -> usize {
        self.points.len()
    }

    /// A fetch, on disk, so that one person queries and the rest of the team
    /// reads the same numbers without credentials or a connection.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        std::fs::write(path, serde_json::to_vec(self)?)?;
        Ok(())
    }

    /// A snapshot, wherever its bytes came from: a file natively, a drop in a
    /// browser.
    pub fn from_json(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut store: Self = serde_json::from_slice(bytes)?;
        store.rebuild_tree();
        Ok(store)
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        Self::from_json(&std::fs::read(path)?)
    }
}

pub enum Fetch {
    Idle,
    Loading,
    Ready(Store),
    Failed(String),
}

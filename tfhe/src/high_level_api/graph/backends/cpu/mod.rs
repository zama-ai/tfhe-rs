//! CPU backend for graph execution
mod ops;
mod scheduler;
#[cfg(test)]
mod tests;
pub mod value;

pub use value::{
    CpuInputList, CpuOutputError, CpuOutputList, RuntimeValue, RuntimeValueConformanceParams,
    RuntimeValueConversionError,
};

/// Options of a [`CpuBackend`].
///
/// Built with a builder-like API from [`Self::default`]:
///
/// ```rust
/// use std::num::NonZeroUsize;
/// use tfhe::graph::{CpuBackend, CpuBackendOptions};
/// use tfhe::{generate_keys, ConfigBuilder};
///
/// let (_client_key, server_key) = generate_keys(ConfigBuilder::default());
///
/// let options = CpuBackendOptions::default()
///     .max_num_workers(NonZeroUsize::new(4).unwrap())
///     .allow_trivial_inputs(true);
/// let backend = CpuBackend::with_options(server_key, options);
/// ```
#[derive(Debug, Clone)]
pub struct CpuBackendOptions {
    max_num_workers: NonZeroUsize,
    allow_trivial_inputs: bool,
}

impl Default for CpuBackendOptions {
    /// `max_num_workers` set to the machine's logical core count, trivial
    /// inputs rejected.
    fn default() -> Self {
        Self {
            max_num_workers: std::thread::available_parallelism()
                .unwrap_or(NonZeroUsize::new(4).expect("4 is non-zero")),
            allow_trivial_inputs: false,
        }
    }
}

impl CpuBackendOptions {
    /// Upper bound on the number of ops executed concurrently (one worker
    /// thread each).
    ///
    /// This is a heuristic for how many ops can run in parallel, not a
    /// reservation of cores.
    /// Each operation use srayon internally and are free to use
    /// every core (see the [`CpuBackend`] doc).
    pub fn max_num_workers(mut self, max_num_workers: NonZeroUsize) -> Self {
        self.max_num_workers = max_num_workers;
        self
    }

    /// Whether to accept trivially encrypted inputs.
    ///
    /// They are rejected by default as they carry no noise,
    /// and thus no security.
    ///
    /// Trivial inputs is meant for tests and debugging only.
    pub fn allow_trivial_inputs(mut self, allow: bool) -> Self {
        self.allow_trivial_inputs = allow;
        self
    }
}

use crate::graph::dialects::hlapi::{FheIntKind, KvKeyKind, ValueKind};
use crate::graph::ExecutionGraph;
use std::num::NonZeroUsize;

/// ExecutionGraph executor that executes a graph on the CPU
///
/// # Parallelism
///
/// Two layers of parallelism are stacked:
/// - the executor runs up to `max_num_workers` *ops* concurrently, one per worker thread;
/// - each op is an integer-layer operation that internally uses rayon's global thread pool, and may
///   therefore use every core on its own.
///
/// `max_num_workers` is thus a cap on the number of ops in flight, not on the
/// number of threads or cores used. Limiting the latter means configuring the
/// rayon global pool.
pub struct CpuBackend {
    pub(crate) sk: crate::ServerKey,
    pub(crate) options: CpuBackendOptions,
}

impl CpuBackend {
    /// Create a CPU backend with the default [`CpuBackendOptions`].
    pub fn new(sk: crate::ServerKey) -> Self {
        Self::with_options(sk, CpuBackendOptions::default())
    }

    /// Create a CPU backend with the given options.
    pub fn with_options(sk: crate::ServerKey, options: CpuBackendOptions) -> Self {
        Self { sk, options }
    }

    pub fn options(&self) -> &CpuBackendOptions {
        &self.options
    }

    /// The conformance parameters inputs are checked against, derived from
    /// this backend's server key and options.
    pub fn input_conformance_params(&self) -> RuntimeValueConformanceParams {
        RuntimeValueConformanceParams::from(&self.sk)
            .allow_trivial(self.options.allow_trivial_inputs)
    }

    /// Resolve the worker count for a given graph
    ///
    /// Take the structural width of the graph, clamped to the configured maximum
    fn pick_num_workers(&self, graph: &ExecutionGraph) -> NonZeroUsize {
        let n = self
            .options
            .max_num_workers
            .get()
            .min(graph.max_concurrent_ops() as usize);
        NonZeroUsize::new(n).unwrap_or(NonZeroUsize::MIN)
    }

    /// Check that every integer value width in `graph` is representable
    /// with this backend's radix encoding, i.e. a non-zero multiple of the
    /// server key's message bits per block.
    pub fn check_graph_compatibility(&self, graph: &ExecutionGraph) -> Result<(), CpuError> {
        let message_bits = u64::from(self.sk.message_modulus().0.ilog2());
        let check = |bits: u64| {
            if bits == 0 || !bits.is_multiple_of(message_bits) {
                Err(CpuError::UnsupportedBitWidth { bits, message_bits })
            } else {
                Ok(())
            }
        };
        for val in graph.ir().walk_vals_linear() {
            match val.get_type() {
                ValueKind::FheUint(n) | ValueKind::FheInt(n) => check(u64::from(n))?,
                ValueKind::KVStore { key: _, value } => {
                    let bits = match value {
                        FheIntKind::Uint(n) | FheIntKind::Int(n) => n,
                    };
                    check(bits.into())?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl super::ExecutionBackend for CpuBackend {
    type Error = CpuError;

    fn execute(
        &mut self,
        graph: &ExecutionGraph,
        inputs: CpuInputList,
    ) -> Result<CpuOutputList, Self::Error> {
        self.check_graph_compatibility(graph)?;
        let n = self.pick_num_workers(graph);
        scheduler::execute_graph(&self.sk, graph, inputs, n, &self.input_conformance_params())
    }
}

/// Possible errors when executing a graph on CPU
#[derive(Debug)]
#[non_exhaustive]
pub enum CpuError {
    InputCountMismatch {
        expected: u32,
        got: u32,
    },
    /// An input does not have the type it was expected to have.
    InputTypeMismatch {
        input_index: u32,
        expected: ValueKind,
        got: ValueKind,
    },
    /// A KVStore input contains a key that does not fit the store's declared
    /// key kind. (Out-of-range *clear integer* inputs surface as
    /// `InputTypeMismatch`: the observed kind of a clear integer is the
    /// minimal width holding its value.)
    KvStoreKeyOutOfRange {
        input_index: u32,
        expected: KvKeyKind,
        key: u128,
    },
    /// An FHE input is not conformant with the executing server key's
    /// parameters (see [`RuntimeValueConformanceParams`]).
    ///
    /// Examples of possible cause are:
    /// It was encrypted under different parameters,
    /// or is not in the fresh state expected of an input
    InputNotConformant {
        input_index: u32,
    },
    /// The graph contains an integer value whose bit-width is not
    /// representable with this backend's radix encoding (not a non-zero
    /// multiple of the key's message bits per block).
    UnsupportedBitWidth {
        bits: u64,
        message_bits: u64,
    },
    /// The op at `node_index` failed while executing: a panic in the op's
    /// implementation, an IR invariant the op found violated, or an internal
    /// executor error surfaced on the op it affected.
    ExecutionError {
        node_index: u32,
        op: &'static str,
        message: String,
    },
}

impl std::fmt::Display for CpuError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InputCountMismatch { expected, got } => {
                write!(f, "input count mismatch: expected {expected}, got {got}")
            }
            Self::InputTypeMismatch {
                input_index,
                expected,
                got,
            } => write!(
                f,
                "invalid type for input {input_index}: expected {expected:?}, got {got:?}"
            ),
            Self::KvStoreKeyOutOfRange {
                input_index,
                expected,
                key,
            } => write!(
                f,
                "KVStore input {input_index} contains key {key} which does not fit its declared key kind {expected:?}"
            ),
            Self::InputNotConformant { input_index } => write!(
                f,
                "input {input_index} is not conformant with the server key's parameters \
                 (encrypted under different parameters, or not a fresh ciphertext)"
            ),
            Self::UnsupportedBitWidth { bits, message_bits } => write!(
                f,
                "graph contains a {bits}-bit integer value, which is not representable \
                 with this key's radix encoding ({message_bits} message bits per block)"
            ),
            Self::ExecutionError {
                node_index,
                op,
                message,
            } => write!(f, "node {node_index} ({op}) failed: {message}"),
        }
    }
}

impl std::error::Error for CpuError {}

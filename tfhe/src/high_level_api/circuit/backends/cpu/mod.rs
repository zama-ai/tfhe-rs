//! CPU backend for circuit execution
mod ops;
mod scheduler;
#[cfg(test)]
mod tests;
pub mod value;

pub use value::{
    CpuInputList, CpuOutputError, CpuOutputList, RuntimeValue, RuntimeValueConversionError,
};

use crate::circuit::dialects::hlapi::{FheIntKind, KvKeyKind, ValueKind};
use crate::circuit::Circuit;
use std::num::NonZeroUsize;

/// Circuit executor that executes a circuit on the CPU
pub struct CpuBackend {
    pub(crate) sk: crate::ServerKey,
    /// Upper bound on the worker pool size.
    /// The actual number of workers used depends on the circuit,
    /// it may be less than this, but never greater
    pub(crate) max_num_workers: NonZeroUsize,
}

impl CpuBackend {
    /// Create a CPU backend with `max_num_workers` derived from the
    /// machine's logical cores, leaving one core for the coordinator thread.
    ///
    /// The actual worker count per execution is further capped by
    /// `circuit.max_concurrent_ops()`.
    pub fn new(sk: crate::ServerKey) -> Self {
        let cpu_threads = std::thread::available_parallelism().map_or(4, NonZeroUsize::get);
        // Leave one logical core for the coordinator thread
        let max = NonZeroUsize::new(cpu_threads.saturating_sub(1)).unwrap_or(NonZeroUsize::MIN);
        Self::with_max_num_workers(sk, max)
    }

    /// Creates a CPU backend with the specified number of `max_num_workers`
    pub fn with_max_num_workers(sk: crate::ServerKey, max_num_workers: NonZeroUsize) -> Self {
        Self {
            sk,
            max_num_workers,
        }
    }

    /// Resolve the worker count for a given circuit
    ///
    /// Take the structural width of the circuit, clamped to the configured maximum
    fn pick_num_workers(&self, circuit: &Circuit) -> usize {
        self.max_num_workers
            .get()
            .min(circuit.max_concurrent_ops() as usize)
            .max(1)
    }

    /// Check that every integer value width in `circuit` is representable
    /// with this backend's radix encoding, i.e. a non-zero multiple of the
    /// server key's message bits per block.
    pub fn check_circuit_compatibility(&self, circuit: &Circuit) -> Result<(), CpuError> {
        let message_bits = u64::from(self.sk.message_modulus().0.ilog2());
        let check = |bits: u64| {
            if bits == 0 || !bits.is_multiple_of(message_bits) {
                Err(CpuError::UnsupportedBitWidth { bits, message_bits })
            } else {
                Ok(())
            }
        };
        for val in circuit.ir().walk_vals_linear() {
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
        circuit: &Circuit,
        inputs: CpuInputList,
    ) -> Result<CpuOutputList, Self::Error> {
        self.check_circuit_compatibility(circuit)?;
        let n = self.pick_num_workers(circuit);
        scheduler::execute_circuit(&self.sk, circuit, inputs, n)
    }
}

/// Possible errors when executing a circuit on CPU
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
    /// An FHE input was encrypted under different parameters than the
    /// executing server key (message/carry modulus mismatch).
    InputParamsMismatch {
        input_index: u32,
        expected_message_modulus: crate::shortint::MessageModulus,
        expected_carry_modulus: crate::shortint::CarryModulus,
        got_message_modulus: crate::shortint::MessageModulus,
        got_carry_modulus: crate::shortint::CarryModulus,
    },
    /// The circuit contains an integer value whose bit-width is not
    /// representable with this backend's radix encoding (not a non-zero
    /// multiple of the key's message bits per block).
    UnsupportedBitWidth {
        bits: u64,
        message_bits: u64,
    },
    /// The execution ended without producing the circuit output at `pos`.
    /// This means the worker threads exited before the circuit completed,
    /// which is an internal error of the executor.
    MissingOutput {
        pos: u32,
    },
    /// Generic something went wrong error
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
            Self::InputParamsMismatch {
                input_index,
                expected_message_modulus,
                expected_carry_modulus,
                got_message_modulus,
                got_carry_modulus,
            } => write!(
                f,
                "input {input_index} was encrypted under different parameters than the \
                 server key: message/carry modulus {}/{} vs the key's {}/{}",
                got_message_modulus.0,
                got_carry_modulus.0,
                expected_message_modulus.0,
                expected_carry_modulus.0,
            ),
            Self::UnsupportedBitWidth { bits, message_bits } => write!(
                f,
                "circuit contains a {bits}-bit integer value, which is not representable \
                 with this key's radix encoding ({message_bits} message bits per block)"
            ),
            Self::MissingOutput { pos } => write!(
                f,
                "execution ended without producing circuit output {pos} (workers exited early)"
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

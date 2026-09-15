pub mod cpu;

use cpu::{CpuInputList, CpuOutputList};

/// A backend capable of executing a [`Circuit`](super::Circuit).
pub trait ExecutionBackend {
    type Error: std::error::Error;

    /// Execute the circuit
    fn execute(
        &mut self,
        circuit: &super::Circuit,
        inputs: CpuInputList,
    ) -> Result<CpuOutputList, Self::Error>;
}

pub mod cpu;

use cpu::{CpuInputList, CpuOutputList};

/// A backend capable of executing a [`Circuit`](super::Circuit).
pub trait ExecutionBackend {
    type InputList;
    type OutputList;
    type Error: std::error::Error;

    /// Convert a CPU input list into this backend's native input list
    fn convert_inputs(&self, inputs: CpuInputList) -> Result<Self::InputList, Self::Error>;

    /// Convert this backend's native output list back to a CPU output
    fn convert_outputs(&self, outputs: Self::OutputList) -> Result<CpuOutputList, Self::Error>;

    /// Execute the circuit
    fn execute(
        &self,
        circuit: &super::Circuit,
        inputs: Self::InputList,
    ) -> Result<Self::OutputList, Self::Error>;

    /// Convenience entry point with CPU types on both ends, wrapping
    /// [`Self::convert_inputs`] → [`Self::execute`] → [`Self::convert_outputs`].
    ///
    /// The `cpu_io` in the name refers to the *I/O types* (CPU/host
    /// ciphertext lists)
    fn execute_cpu_io(
        &self,
        circuit: &super::Circuit,
        inputs: CpuInputList,
    ) -> Result<CpuOutputList, Self::Error> {
        let native = self.convert_inputs(inputs)?;
        self.convert_outputs(self.execute(circuit, native)?)
    }
}

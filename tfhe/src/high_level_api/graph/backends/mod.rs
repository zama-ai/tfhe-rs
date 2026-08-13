pub mod cpu;

use cpu::{CpuInputList, CpuOutputList};

/// A backend capable of executing a [`ExecutionGraph`](super::ExecutionGraph).
pub trait ExecutionBackend {
    type Error: std::error::Error;

    /// Execute the graph
    fn execute(
        &mut self,
        graph: &super::ExecutionGraph,
        inputs: CpuInputList,
    ) -> Result<CpuOutputList, Self::Error>;
}

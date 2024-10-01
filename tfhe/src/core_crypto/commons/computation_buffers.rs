//! Module containing primitives to manage computations buffers for memory optimized fft primitives.

use dyn_stack::PodStack;

#[derive(Default)]
/// Struct containing a resizable buffer that can be used with a `PodStack` to provide memory
/// buffers for memory optimized fft primitives.
pub struct ComputationBuffers {
    memory: Vec<u8>,
}

impl ComputationBuffers {
    /// Create a new empty [`ComputationBuffers`] instance.
    pub fn new() -> Self {
        Self { memory: Vec::new() }
    }

    /// Resize the underlying memory buffer, reallocating memory when capacity exceeds the current
    /// buffer capacity.
    pub fn resize(&mut self, capacity: usize) {
        self.memory.resize(capacity, 0);
    }

    /// Return a `PodStack` borrowoing from the managed memory buffer for use with optimized fft
    /// primitives or other functions using `PodStack` to manage temporary memory.
    pub fn stack(&mut self) -> &mut PodStack {
        PodStack::new(&mut self.memory)
    }
}

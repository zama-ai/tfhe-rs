//! Module containing primitives to manage computations buffers for memory optimized fft primitives.

use core::mem::MaybeUninit;
use dyn_stack::DynStack;

#[derive(Default)]
/// Struct containing a resizable buffer that can be used with a `DynStack` to provide memory
/// buffers for memory optimized fft primitives.
pub struct ComputationBuffers {
    memory: Vec<MaybeUninit<u8>>,
}

impl ComputationBuffers {
    /// Create a new emtpy [`ComputationBuffers`] instance.
    pub fn new() -> Self {
        ComputationBuffers { memory: Vec::new() }
    }

    /// Resize the underlying memory buffer, reallocating memory when capacity exceeds the current
    /// buffer capacity.
    pub fn resize(&mut self, capacity: usize) {
        self.memory.resize_with(capacity, MaybeUninit::uninit);
    }

    /// Return a `DynStack` borrowoing from the managed memory buffer for use with optimized fft
    /// primitives or other functions using `DynStack` to manage temporary memory.
    pub fn stack(&mut self) -> DynStack<'_> {
        DynStack::new(&mut self.memory)
    }
}

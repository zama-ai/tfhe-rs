use core::mem::MaybeUninit;
use dyn_stack::DynStack;

#[derive(Default)]
pub struct FftBuffers {
    memory: Vec<MaybeUninit<u8>>,
}

impl FftBuffers {
    pub fn new() -> Self {
        FftBuffers { memory: Vec::new() }
    }

    pub fn resize(&mut self, capacity: usize) {
        self.memory.resize_with(capacity, MaybeUninit::uninit);
    }

    pub fn stack(&mut self) -> DynStack<'_> {
        DynStack::new(&mut self.memory)
    }
}

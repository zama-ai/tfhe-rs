use tfhe::prelude::FheWait;
use tfhe::{FheBool, FheInt, FheIntId, FheUint, FheUintId, SquashedNoiseFheUint};

pub trait BenchWait {
    fn wait_bench(&self);
}

impl<Id: FheUintId> BenchWait for FheUint<Id> {
    fn wait_bench(&self) {
        self.wait()
    }
}

impl<Id: FheIntId> BenchWait for FheInt<Id> {
    fn wait_bench(&self) {
        self.wait()
    }
}

impl BenchWait for FheBool {
    fn wait_bench(&self) {
        self.wait()
    }
}

impl BenchWait for SquashedNoiseFheUint {
    fn wait_bench(&self) {
        self.wait()
    }
}

impl<T1: FheWait, T2> BenchWait for (T1, T2) {
    fn wait_bench(&self) {
        self.0.wait()
    }
}

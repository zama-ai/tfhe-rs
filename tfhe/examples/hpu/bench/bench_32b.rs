use tfhe::prelude::*;
mod bench_macro;
use bench_macro::*;

impl_hpu_bench!(FheUint32, FheUint32Id, u32, 32);

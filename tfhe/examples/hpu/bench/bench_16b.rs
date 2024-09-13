use tfhe::prelude::*;
mod bench_macro;
use bench_macro::*;

impl_hpu_bench!(FheUint16, FheUint16Id, u16, 16);

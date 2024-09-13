use tfhe::prelude::*;
mod bench_macro;
use bench_macro::*;

impl_hpu_bench!(FheUint8, FheUint8Id, u8, 8);

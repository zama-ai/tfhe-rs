use tfhe::prelude::*;
mod bench_macro;
use bench_macro::*;

impl_hpu_bench!(FheUint64, FheUint64Id, u64, 64);

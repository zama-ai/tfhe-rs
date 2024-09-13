use tfhe::prelude::*;
mod bench_macro;
use bench_macro::*;

use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::prelude::DefaultRandomGenerator;

impl_hpu_bench!(FheUint64, FheUint64Id, u64, 64);

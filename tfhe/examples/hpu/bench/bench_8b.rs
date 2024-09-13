use tfhe::prelude::*;
mod bench_macro;
use bench_macro::*;

use tfhe::core_crypto::commons::generators::DeterministicSeeder;
use tfhe::core_crypto::prelude::DefaultRandomGenerator;

impl_hpu_bench!(FheUint8, FheUint8Id, u8, 8);

use crate::utilities::{write_to_json, OperatorType};
use concrete_csprng::seeders::Seed;
use criterion::{black_box, Criterion};
use itertools::iproduct;
use std::vec::IntoIter;
use tfhe::integer::keycache::KEY_CACHE;
use tfhe::integer::IntegerKeyKind;
use tfhe::keycache::NamedParam;
use tfhe::shortint::parameters::*;

/// An iterator that yields a succession of combinations
/// of parameters and a num_block to achieve a certain bit_size ciphertext
/// in radix decomposition
struct ParamsAndNumBlocksIter {
    params_and_bit_sizes: itertools::Product<IntoIter<PBSParameters>, IntoIter<u64>>,
}

impl Default for ParamsAndNumBlocksIter {
    fn default() -> Self {
        let params = vec![PARAM_MESSAGE_2_CARRY_2_KS_PBS.into()];
        let bit_sizes = vec![64];
        let params_and_bit_sizes = iproduct!(params, bit_sizes);
        Self {
            params_and_bit_sizes,
        }
    }
}

impl Iterator for ParamsAndNumBlocksIter {
    type Item = (PBSParameters, u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        let (param, bit_size) = self.params_and_bit_sizes.next()?;
        let num_block =
            (bit_size as f64 / (param.message_modulus().0 as f64).log(2.0)).ceil() as u64;

        Some((param, num_block, bit_size))
    }
}

pub fn unsigned_oprf(c: &mut Criterion) {
    let bench_name = "integer::unsigned_oprf";

    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));

    for (param, num_block, bit_size) in ParamsAndNumBlocksIter::default() {
        let (_, sk) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

        let bench_id = format!("{}::{}::{}_bits", bench_name, param.name(), bit_size);
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                _ = black_box(sk.par_generate_oblivious_pseudo_random_unsigned_integer(
                    Seed(0),
                    bit_size,
                    num_block,
                ));
            })
        });

        write_to_json::<u64, _>(
            &bench_id,
            param,
            param.name(),
            "oprf",
            &OperatorType::Atomic,
            bit_size as u32,
            vec![param.message_modulus().0.ilog2(); num_block as usize],
        );
    }

    bench_group.finish()
}

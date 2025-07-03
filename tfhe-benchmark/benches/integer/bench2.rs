#![allow(dead_code)]

mod oprf;
use diol::prelude::*;
use rand::prelude::*;
use rayon::prelude::*;
use tfhe::integer::keycache::KEY_CACHE;
use tfhe::integer::prelude::*;
use tfhe::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey, U256};
use tfhe::keycache::NamedParam;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

fn bench_div(bencher: Bencher, _bit_size: usize) {
    let (cks, sks) = KEY_CACHE.get_from_params(PARAM_MESSAGE_2_CARRY_2, IntegerKeyKind::Radix);
    let mut rng = rand::thread_rng();
    let num_blocks = 32;

    let clear_0 = rng.gen::<u64>();
    let ct_0 = cks.encrypt_radix(clear_0, num_blocks);

    let clear_1 = rng.gen::<u64>();
    let ct_1 = cks.encrypt_radix(clear_1, num_blocks);

    bencher.bench(|| {
        let (q, r) = sks.div_rem_parallelized(&ct_0, &ct_1);
        black_box(q);
        black_box(r);
    });
}

fn main() {
    let bench = Bench::from_args().unwrap();
    bench.register("div", bench_div, [64usize]);
    bench.run().unwrap();
}

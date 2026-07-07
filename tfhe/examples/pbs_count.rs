// Run with:
//   cargo run --release --example pbs_count --features="integer,pbs-stats"

use tfhe::prelude::*;
use tfhe::*;

fn pbs_count<T, S>(cks: &ClientKey, op_name: &str, op: &dyn Fn(T, T))
where
    T: FheEncrypt<S, ClientKey>,
    S: From<u8>,
{
    let bits = size_of::<S>() * 8;
    let a = T::encrypt(S::from(42), cks);
    let b = T::encrypt(S::from(69), cks);

    reset_pbs_count();
    op(a, b);
    println!("{bits:<3} bits | {op_name:<3} | {} PBS", get_pbs_count());
}

fn main() {
    let config = ConfigBuilder::default().build();
    let (cks, sks) = generate_keys(config);
    set_server_key(sks);

    pbs_count::<FheUint64, u64>(&cks, "mul", &|a, b| {
        let _ = a * b;
    });
    pbs_count::<FheUint128, u128>(&cks, "mul", &|a, b| {
        let _ = a * b;
    });
}

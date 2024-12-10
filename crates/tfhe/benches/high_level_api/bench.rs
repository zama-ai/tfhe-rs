use criterion::{black_box, Criterion};
use rand::prelude::*;
use std::fmt::Write;
use std::ops::*;
use tfhe::prelude::*;
use tfhe::shortint::parameters::*;
use tfhe::{
    set_server_key, ClientKey, CompressedServerKey, ConfigBuilder, FheUint10, FheUint12,
    FheUint128, FheUint14, FheUint16, FheUint2, FheUint32, FheUint4, FheUint6, FheUint64, FheUint8,
};

fn bench_fhe_type<FheType>(c: &mut Criterion, client_key: &ClientKey, type_name: &str)
where
    FheType: FheEncrypt<u128, ClientKey>,
    for<'a> &'a FheType: Add<&'a FheType, Output = FheType>
        + Sub<&'a FheType, Output = FheType>
        + Mul<&'a FheType, Output = FheType>
        + BitAnd<&'a FheType, Output = FheType>
        + BitOr<&'a FheType, Output = FheType>
        + BitXor<&'a FheType, Output = FheType>
        + Shl<&'a FheType, Output = FheType>
        + Shr<&'a FheType, Output = FheType>
        + RotateLeft<&'a FheType, Output = FheType>
        + RotateRight<&'a FheType, Output = FheType>
        + OverflowingAdd<&'a FheType, Output = FheType>
        + OverflowingSub<&'a FheType, Output = FheType>,
{
    let mut bench_group = c.benchmark_group(type_name);

    let mut rng = thread_rng();

    let lhs = FheType::encrypt(rng.gen(), client_key);
    let rhs = FheType::encrypt(rng.gen(), client_key);

    let mut name = String::with_capacity(255);

    write!(name, "add({type_name}, {type_name})").unwrap();
    bench_group.bench_function(&name, |b| b.iter(|| black_box(&lhs + &rhs)));
    name.clear();

    write!(name, "overflowing_add({type_name}, {type_name})").unwrap();
    bench_group.bench_function(&name, |b| {
        b.iter(|| black_box((&lhs).overflowing_add(&rhs)))
    });
    name.clear();

    write!(name, "overflowing_sub({type_name}, {type_name})").unwrap();
    bench_group.bench_function(&name, |b| b.iter(|| black_box(lhs.overflowing_sub(&rhs))));
    name.clear();

    write!(name, "sub({type_name}, {type_name})").unwrap();
    bench_group.bench_function(&name, |b| b.iter(|| black_box(&lhs - &rhs)));
    name.clear();

    write!(name, "mul({type_name}, {type_name})").unwrap();
    bench_group.bench_function(&name, |b| b.iter(|| black_box(&lhs * &rhs)));
    name.clear();

    write!(name, "bitand({type_name}, {type_name})").unwrap();
    bench_group.bench_function(&name, |b| b.iter(|| black_box(&lhs & &rhs)));
    name.clear();

    write!(name, "bitor({type_name}, {type_name})").unwrap();
    bench_group.bench_function(&name, |b| b.iter(|| black_box(&lhs | &rhs)));
    name.clear();

    write!(name, "bitxor({type_name}, {type_name})").unwrap();
    bench_group.bench_function(&name, |b| b.iter(|| black_box(&lhs ^ &rhs)));
    name.clear();

    write!(name, "shl({type_name}, {type_name})").unwrap();
    bench_group.bench_function(&name, |b| b.iter(|| black_box(&lhs << &rhs)));
    name.clear();

    write!(name, "shr({type_name}, {type_name})").unwrap();
    bench_group.bench_function(&name, |b| b.iter(|| black_box(&lhs >> &rhs)));
    name.clear();

    write!(name, "rotl({type_name}, {type_name})").unwrap();
    bench_group.bench_function(&name, |b| b.iter(|| black_box((&lhs).rotate_left(&rhs))));
    name.clear();

    write!(name, "rotr({type_name}, {type_name})").unwrap();
    bench_group.bench_function(&name, |b| b.iter(|| black_box((&lhs).rotate_right(&rhs))));
    name.clear();
}

macro_rules! bench_type {
    ($fhe_type:ident) => {
        ::paste::paste! {
            fn [<bench_ $fhe_type:snake>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type::<$fhe_type>(c, cks, stringify!($fhe_type));
            }
        }
    };
}

bench_type!(FheUint2);
bench_type!(FheUint4);
bench_type!(FheUint6);
bench_type!(FheUint8);
bench_type!(FheUint10);
bench_type!(FheUint12);
bench_type!(FheUint14);
bench_type!(FheUint16);
bench_type!(FheUint32);
bench_type!(FheUint64);
bench_type!(FheUint128);

fn main() {
    let config = ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS).build();
    let cks = ClientKey::generate(config);
    let compressed_sks = CompressedServerKey::new(&cks);

    set_server_key(compressed_sks.decompress());

    let mut c = Criterion::default().configure_from_args();

    bench_fhe_uint2(&mut c, &cks);
    bench_fhe_uint4(&mut c, &cks);
    bench_fhe_uint6(&mut c, &cks);
    bench_fhe_uint8(&mut c, &cks);
    bench_fhe_uint10(&mut c, &cks);
    bench_fhe_uint12(&mut c, &cks);
    bench_fhe_uint14(&mut c, &cks);
    bench_fhe_uint16(&mut c, &cks);
    bench_fhe_uint32(&mut c, &cks);
    bench_fhe_uint64(&mut c, &cks);
    bench_fhe_uint128(&mut c, &cks);

    c.final_summary();
}

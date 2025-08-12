use benchmark::utilities::{write_to_json, OperatorType};
use criterion::{black_box, Criterion};
use rand::prelude::*;
use std::ops::*;
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
use tfhe::{
    ClientKey, CompressedServerKey, FheUint10, FheUint12, FheUint128, FheUint14, FheUint16,
    FheUint2, FheUint32, FheUint4, FheUint6, FheUint64, FheUint8,
};

fn bench_fhe_type<FheType>(
    c: &mut Criterion,
    client_key: &ClientKey,
    type_name: &str,
    bit_size: usize,
) where
    FheType: FheEncrypt<u128, ClientKey>,
    FheType: FheWait,
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
    let bench_prefix = "hlapi::ops";

    let mut rng = thread_rng();

    let param = client_key.computation_parameters();
    let param_name = param.name();
    let bit_size = bit_size as u32;

    let write_record = |bench_id: String, display_name| {
        write_to_json::<u64, _>(
            &bench_id,
            param,
            &param_name,
            display_name,
            &OperatorType::Atomic,
            bit_size,
            vec![],
        );
    };

    let lhs = FheType::encrypt(rng.gen(), client_key);
    let rhs = FheType::encrypt(rng.gen(), client_key);

    let mut bench_id;

    bench_id = format!("{bench_prefix}::add::{param_name}::{bit_size}_bits");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = &lhs + &rhs;
            res.wait();
            black_box(res)
        })
    });
    write_record(bench_id, "add");

    #[cfg(not(feature = "hpu"))]
    {
        bench_id = format!("{bench_prefix}::overflowing_add::{param_name}::{bit_size}_bits");
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                let (res, flag) = lhs.overflowing_add(&rhs);
                res.wait();
                black_box((res, flag))
            })
        });
        write_record(bench_id, "overflowing_add");
    }

    #[cfg(not(feature = "hpu"))]
    {
        bench_id = format!("{bench_prefix}::overflowing_sub::{param_name}::{bit_size}_bits");
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                let (res, flag) = lhs.overflowing_sub(&rhs);
                res.wait();
                black_box((res, flag))
            })
        });
        write_record(bench_id, "overflowing_sub");
    }

    bench_id = format!("{bench_prefix}::sub::{param_name}::{bit_size}_bits");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = &lhs - &rhs;
            res.wait();
            black_box(res)
        })
    });
    write_record(bench_id, "sub");

    bench_id = format!("{bench_prefix}::mul::{param_name}::{bit_size}_bits");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = &lhs * &rhs;
            res.wait();
            black_box(res)
        })
    });
    write_record(bench_id, "mul");

    bench_id = format!("{bench_prefix}::bitand::{param_name}::{bit_size}_bits");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = &lhs & &rhs;
            res.wait();
            black_box(res)
        })
    });
    write_record(bench_id, "bitand");

    bench_id = format!("{bench_prefix}::bitor::{param_name}::{bit_size}_bits");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = &lhs | &rhs;
            res.wait();
            black_box(res)
        })
    });
    write_record(bench_id, "bitor");

    bench_id = format!("{bench_prefix}::bitxor::{param_name}::{bit_size}_bits");
    bench_group.bench_function(&bench_id, |b| {
        b.iter(|| {
            let res = &lhs ^ &rhs;
            res.wait();
            black_box(res)
        })
    });
    write_record(bench_id, "bitxor");

    #[cfg(not(feature = "hpu"))]
    {
        bench_id = format!("{bench_prefix}::left_shift::{param_name}::{bit_size}_bits");
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                let res = &lhs << &rhs;
                res.wait();
                black_box(res)
            })
        });
        write_record(bench_id, "left_shift");

        bench_id = format!("{bench_prefix}::right_shift::{param_name}::{bit_size}_bits");
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                let res = &lhs >> &rhs;
                res.wait();
                black_box(res)
            })
        });
        write_record(bench_id, "right_shift");

        bench_id = format!("{bench_prefix}::left_rotate::{param_name}::{bit_size}_bits");
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                let res = (&lhs).rotate_left(&rhs);
                res.wait();
                black_box(res)
            })
        });
        write_record(bench_id, "left_rotate");

        bench_id = format!("{bench_prefix}::right_rotate::{param_name}::{bit_size}_bits");
        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                let res = (&lhs).rotate_right(&rhs);
                res.wait();
                black_box(res)
            })
        });
        write_record(bench_id, "right_rotate");
    }
}

macro_rules! bench_type {
    ($fhe_type:ident) => {
        ::paste::paste! {
            fn [<bench_ $fhe_type:snake>](c: &mut Criterion, cks: &ClientKey) {
                bench_fhe_type::<$fhe_type>(c, cks, stringify!($fhe_type), $fhe_type::num_bits());
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
    #[cfg(feature = "hpu")]
    let cks = {
        // Hpu is enable, start benchmark on Hpu hw accelerator
        use tfhe::tfhe_hpu_backend::prelude::*;
        use tfhe::{set_server_key, Config};

        // Use environment variable to construct path to configuration file
        let config_path = ShellString::new(
            "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_config.toml".to_string(),
        );
        let hpu_device = HpuDevice::from_config(&config_path.expand());

        let config = Config::from_hpu_device(&hpu_device);
        let cks = ClientKey::generate(config);
        let compressed_sks = CompressedServerKey::new(&cks);

        set_server_key((hpu_device, compressed_sks));
        cks
    };
    #[cfg(not(feature = "hpu"))]
    let cks = {
        use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        use tfhe::{set_server_key, ConfigBuilder};
        let config = ConfigBuilder::with_custom_parameters(
            BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        )
        .build();
        let cks = ClientKey::generate(config);
        let compressed_sks = CompressedServerKey::new(&cks);

        set_server_key(compressed_sks.decompress());
        cks
    };

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

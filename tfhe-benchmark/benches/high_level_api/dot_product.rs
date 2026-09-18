use benchmark::high_level_api::type_display::TypeTagExt;
use benchmark::params_aliases::{
    BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use benchmark::utilities::{throughput_num_threads, write_to_json, OperatorType};
use benchmark_spec::{
    get_bench_type, BenchmarkSpec, BenchmarkType, HlIntegerOp, HlapiBench, OperandType,
};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rand::Rng;
use rayon::prelude::*;
use std::hint::black_box;
use std::time::Duration;
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
use tfhe::shortint::AtomicPatternParameters;
use tfhe::{
    get_pbs_count, reset_pbs_count, set_server_key, ClientKey, CompressedServerKey, ConfigBuilder,
    FheUint64,
};

const ARRAY_LENGTHS: [usize; 5] = [8, 16, 32, 64, 128];

fn bench_dot_product(c: &mut Criterion, parameter: AtomicPatternParameters) {
    let config = ConfigBuilder::with_custom_parameters(parameter).build();
    let client_key = ClientKey::generate(config);
    let server_key = CompressedServerKey::new(&client_key).decompress_to_gpu();
    rayon::broadcast(|_| set_server_key(server_key.clone()));
    set_server_key(server_key);

    let parameter_name = client_key.computation_parameters().name();
    let bench_type = get_bench_type();
    let mut rng = rand::thread_rng();
    let mut group = c.benchmark_group(HlIntegerOp::DotProductParallel.to_string());
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(30));

    for length in ARRAY_LENGTHS {
        let clear_lhs = (0..length).map(|_| rng.gen()).collect::<Vec<u64>>();
        let clear_rhs = (0..length).map(|_| rng.gen()).collect::<Vec<u64>>();
        let encrypted_lhs = clear_lhs
            .iter()
            .copied()
            .map(|value| FheUint64::encrypt(value, &client_key))
            .collect::<Vec<_>>();

        let expected = clear_lhs
            .iter()
            .copied()
            .zip(clear_rhs.iter().copied())
            .fold(0u64, |acc, (lhs, rhs)| {
                acc.wrapping_add(lhs.wrapping_mul(rhs))
            });
        reset_pbs_count();
        let result = FheUint64::dot_product_parallel(&encrypted_lhs, &clear_rhs);
        result.wait();
        let pbs_count = get_pbs_count().max(1);
        let decrypted: u64 = result.decrypt(&client_key);
        assert_eq!(decrypted, expected);

        let spec = BenchmarkSpec::new_hlapi(
            HlapiBench::Ops(HlIntegerOp::DotProductParallel),
            &parameter_name,
            OperandType::PlainText,
            Some(FheUint64::type_tag()),
            bench_type,
            Some(length as u64),
        );
        let bench_id = spec.to_string();

        match bench_type {
            BenchmarkType::Latency => {
                group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        let result = FheUint64::dot_product_parallel(
                            black_box(&encrypted_lhs),
                            black_box(&clear_rhs),
                        );
                        result.wait();
                        black_box(result)
                    })
                });
            }
            BenchmarkType::Throughput => {
                let message_bits = client_key
                    .computation_parameters()
                    .message_modulus()
                    .0
                    .ilog2() as usize;
                let num_blocks = length * 64 / message_bits;
                let num_ops = 4 * throughput_num_threads(num_blocks, pbs_count).max(1) as usize;
                let inputs = (0..num_ops)
                    .map(|_| {
                        let clear_lhs = (0..length).map(|_| rng.gen()).collect::<Vec<u64>>();
                        let clear_rhs = (0..length).map(|_| rng.gen()).collect::<Vec<u64>>();
                        let encrypted_lhs = clear_lhs
                            .iter()
                            .copied()
                            .map(|value| FheUint64::encrypt(value, &client_key))
                            .collect::<Vec<_>>();
                        (encrypted_lhs, clear_rhs)
                    })
                    .collect::<Vec<_>>();

                group.throughput(Throughput::Elements(num_ops as u64));
                group.bench_function(&bench_id, |b| {
                    b.iter(|| {
                        inputs.par_iter().for_each(|(encrypted_lhs, clear_rhs)| {
                            let result = FheUint64::dot_product_parallel(
                                black_box(encrypted_lhs),
                                black_box(clear_rhs),
                            );
                            result.wait();
                            black_box(result);
                        })
                    })
                });
            }
        }

        write_to_json(
            &spec,
            HlIntegerOp::DotProductParallel.to_string(),
            &OperatorType::Atomic,
            64,
            vec![],
        );
    }

    group.finish();
}

fn dot_product_classical(c: &mut Criterion) {
    bench_dot_product(
        c,
        BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
    );
}

fn dot_product_multi_bit(c: &mut Criterion) {
    bench_dot_product(
        c,
        BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128.into(),
    );
}

criterion_group!(
    dot_product_group,
    dot_product_classical,
    dot_product_multi_bit
);
criterion_main!(dot_product_group);

use benchmark::params_aliases::BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use benchmark::utilities::{write_to_json, OperatorType};
use criterion::{black_box, Criterion};
use tfhe::integer::keycache::KEY_CACHE;
use tfhe::integer::{IntegerKeyKind, RadixClientKey};
use tfhe::keycache::NamedParam;
use tfhe::shortint::AtomicPatternParameters;
use tfhe::MatchValues;

fn match_value_scenarios() -> Vec<(usize, usize, usize)> {
    vec![(64, 10, 32), (8, 256, 4)]
}

pub fn match_value(c: &mut Criterion) {
    let bench_name = "integer::match_value";
    let mut group = c.benchmark_group(bench_name);
    group.sample_size(15);

    let param = BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let atomic_param: AtomicPatternParameters = param.into();
    let param_name = param.name();

    let (cpu_cks, cpu_sks) = KEY_CACHE.get_from_params(atomic_param, IntegerKeyKind::Radix);

    for (bits, num_elements, num_blocks) in match_value_scenarios() {
        let bench_id = format!("{bench_name}::{param_name}::{bits}bit_{num_elements}elements");

        let cks = RadixClientKey::from((cpu_cks.clone(), num_blocks));

        let mapping_data: Vec<(u64, u64)> = (0..num_elements as u64).map(|i| (i, i)).collect();
        let match_values = MatchValues::new(mapping_data).expect("Invalid match values");

        let input_val = 1u64;
        let ct_input = cks.encrypt(input_val);

        group.bench_function(&bench_id, |b| {
            b.iter(|| {
                black_box(cpu_sks.match_value_parallelized(&ct_input, &match_values));
            })
        });

        write_to_json::<u64, _>(
            &bench_id,
            atomic_param,
            param.name(),
            "match_value",
            &OperatorType::Atomic,
            bits as u32,
            vec![atomic_param.message_modulus().0.ilog2(); bits],
        );
    }
    group.finish();
}

#[cfg(feature = "gpu")]
pub mod cuda {
    use super::*;
    use tfhe::core_crypto::gpu::CudaStreams;
    use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
    use tfhe::integer::gpu::CudaServerKey;

    pub fn cuda_match_value(c: &mut Criterion) {
        let bench_name = "integer::cuda::match_value";
        let mut group = c.benchmark_group(bench_name);
        group.sample_size(15);

        let param = BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let atomic_param: AtomicPatternParameters = param.into();
        let param_name = param.name();

        let streams = CudaStreams::new_multi_gpu();

        let (cpu_cks, _) = KEY_CACHE.get_from_params(atomic_param, IntegerKeyKind::Radix);
        let sks = CudaServerKey::new(&cpu_cks, &streams);

        for (bits, num_elements, num_blocks) in match_value_scenarios() {
            let bench_id = format!("{bench_name}::{param_name}::{bits}bit_{num_elements}elements");

            let cks = RadixClientKey::from((cpu_cks.clone(), num_blocks));

            let mapping_data: Vec<(u64, u64)> = (0..num_elements as u64).map(|i| (i, i)).collect();
            let match_values = MatchValues::new(mapping_data).expect("Invalid match values");

            let input_val = 1u64;
            let ct_input = cks.encrypt(input_val);
            let d_ct_input =
                CudaUnsignedRadixCiphertext::from_radix_ciphertext(&ct_input, &streams);

            group.bench_function(&bench_id, |b| {
                b.iter(|| {
                    black_box(sks.match_value(&d_ct_input, &match_values, &streams));
                })
            });

            write_to_json::<u64, _>(
                &bench_id,
                atomic_param,
                param.name(),
                "match_value",
                &OperatorType::Atomic,
                bits as u32,
                vec![atomic_param.message_modulus().0.ilog2(); bits],
            );
        }
        group.finish();
    }
}

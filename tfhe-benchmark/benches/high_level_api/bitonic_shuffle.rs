use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
use criterion::{black_box, criterion_group, Criterion};
use rand::Rng;
use tfhe::core_crypto::seeders::UnixSeeder;
use tfhe::prelude::*;
use tfhe::{bitonic_shuffle, set_server_key, ClientKey, ConfigBuilder, FheUint64, ServerKey};

fn bitonic_shuffle_bench(c: &mut Criterion, bench_name: &str, cks: &ClientKey) {
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group.sample_size(10);

    let mut rng = rand::thread_rng();

    for num_elements in [16, 32] {
        let clear_values: Vec<u64> = (0..num_elements).map(|_| rng.gen()).collect();
        let encrypted: Vec<FheUint64> = clear_values
            .iter()
            .map(|&v| FheUint64::encrypt(v, cks))
            .collect();

        let bench_id = format!("{bench_name}::n_{num_elements}");

        bench_group.bench_function(&bench_id, |b| {
            b.iter(|| {
                let mut seeder = UnixSeeder::new(0);
                let result = bitonic_shuffle(
                    encrypted.clone(),
                    tfhe::integer::server_key::BitonicShuffleKeySize::NumBlocks(16),
                    &mut seeder,
                )
                .expect("shuffle failed");
                black_box(result);
            })
        });
    }

    bench_group.finish();
}

pub fn bitonic_shuffle_cpu(c: &mut Criterion) {
    let param = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let config = ConfigBuilder::with_custom_parameters(param).build();
    let cks = ClientKey::generate(config);
    let sks = ServerKey::new(&cks);

    rayon::broadcast(|_| set_server_key(sks.clone()));
    set_server_key(sks);

    bitonic_shuffle_bench(c, "hlapi::bitonic_shuffle_cpu", &cks);
}

criterion_group!(bitonic_shuffle_group, bitonic_shuffle_cpu);
criterion::criterion_main!(bitonic_shuffle_group);

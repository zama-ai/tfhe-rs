use criterion::{black_box, criterion_group, criterion_main, Criterion};
#[cfg(all(target_arch = "x86_64", target_feature = "aes"))]
use tfhe_csprng::generators::AesniRandomGenerator as ActivatedRandomGenerator;
#[cfg(not(all(target_arch = "x86_64", target_feature = "aes")))]
use tfhe_csprng::generators::SoftwareRandomGenerator as ActivatedRandomGenerator;
use tfhe_csprng::generators::{BytesPerChild, ChildrenCount, RandomGenerator};
use tfhe_csprng::seeders::{RdseedSeeder, Seeder};

// The number of bytes to generate during one benchmark iteration.
const N_GEN: usize = 1_000_000;

fn parent_generate(c: &mut Criterion) {
    let mut seeder = RdseedSeeder::new();
    let mut generator = ActivatedRandomGenerator::new(seeder.seed());
    c.bench_function("parent_generate", |b| {
        b.iter(|| {
            (0..N_GEN).for_each(|_| {
                generator.next();
            })
        })
    });
}

fn child_generate(c: &mut Criterion) {
    let mut seeder = RdseedSeeder::new();
    let mut generator = ActivatedRandomGenerator::new(seeder.seed());
    let mut generator = generator
        .try_fork(ChildrenCount(1), BytesPerChild(N_GEN * 10_000))
        .unwrap()
        .next()
        .unwrap();
    c.bench_function("child_generate", |b| {
        b.iter(|| {
            (0..N_GEN).for_each(|_| {
                generator.next();
            })
        })
    });
}

fn fork(c: &mut Criterion) {
    let mut seeder = RdseedSeeder::new();
    let mut generator = ActivatedRandomGenerator::new(seeder.seed());
    c.bench_function("fork", |b| {
        b.iter(|| {
            black_box(
                generator
                    .try_fork(ChildrenCount(2048), BytesPerChild(2048))
                    .unwrap(),
            )
        })
    });
}

criterion_group!(benches, parent_generate, child_generate, fork);
criterion_main!(benches);

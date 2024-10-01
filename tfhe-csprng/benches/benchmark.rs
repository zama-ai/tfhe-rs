use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tfhe_csprng::generators::{
    BytesPerChild, ChildrenCount, DefaultRandomGenerator, RandomGenerator,
};
#[cfg(target_os = "macos")]
use tfhe_csprng::seeders::AppleSecureEnclaveSeeder as ActivatedSeeder;
#[cfg(all(
    not(target_os = "macos"),
    target_arch = "x86_64",
    target_feature = "rdseed"
))]
use tfhe_csprng::seeders::RdseedSeeder as ActivatedSeeder;
#[cfg(all(
    not(target_os = "macos"),
    not(all(target_arch = "x86_64", target_feature = "rdseed")),
    target_family = "unix"
))]
use tfhe_csprng::seeders::UnixSeeder as ActivatedSeeder;

use tfhe_csprng::seeders::Seeder;

// The number of bytes to generate during one benchmark iteration.
const N_GEN: usize = 1_000_000;

fn new_seeder() -> ActivatedSeeder {
    #[cfg(target_os = "macos")]
    {
        ActivatedSeeder
    }
    #[cfg(all(
        not(target_os = "macos"),
        target_arch = "x86_64",
        target_feature = "rdseed"
    ))]
    {
        ActivatedSeeder::new()
    }
    #[cfg(all(
        not(target_os = "macos"),
        not(all(target_arch = "x86_64", target_feature = "rdseed")),
        target_family = "unix"
    ))]
    {
        ActivatedSeeder::new(0)
    }
}

fn parent_generate(c: &mut Criterion) {
    let mut seeder = new_seeder();
    let mut generator = DefaultRandomGenerator::new(seeder.seed());
    c.bench_function("parent_generate", |b| {
        b.iter(|| {
            (0..N_GEN).for_each(|_| {
                generator.next();
            })
        })
    });
}

fn child_generate(c: &mut Criterion) {
    let mut seeder = new_seeder();
    let mut generator = DefaultRandomGenerator::new(seeder.seed());
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
    let mut seeder = new_seeder();
    let mut generator = DefaultRandomGenerator::new(seeder.seed());
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

//! Benchmark comparing CPU MSM vs GPU MSM for BLS12-446
//!
//! This benchmark measures the performance of multi-scalar multiplication (MSM)
//! for both G1 and G2 points on the BLS12-446 curve.
//!
//! CPU benchmarks use the arkworks-based `G1Affine::multi_mul_scalar` /
//! `G2Affine::multi_mul_scalar`. GPU benchmarks (gated behind the
//! `gpu-zk` feature) call `tfhe_zk_pok::gpu::g1_msm_gpu` /
//! `tfhe_zk_pok::gpu::g2_msm_gpu` directly, which dispatch to the
//! zk-cuda-backend.
//!
//! ## Running the benchmarks
//!
//! ```bash
//! # CPU only
//! cargo bench --package tfhe-benchmark --bench zk-msm
//!
//! # CPU and GPU
//! cargo bench --package tfhe-benchmark --bench zk-msm --features gpu-zk
//! ```

use benchmark::utilities::{write_to_json, OperatorType};
use benchmark_spec::zk::msm::{MsmBench, MsmFlavor};
use benchmark_spec::{get_bench_type, Backend, BenchmarkSpec, BenchmarkType};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rayon::prelude::*;
use std::hint::black_box;
use std::time::Duration;

use tfhe_zk_pok::curve_api::bls12_446::{G1Affine, G2Affine, Zp, G1, G2};
use tfhe_zk_pok::curve_api::CurveGroupOps;

const MSM_SIZES: &[usize] = &[100, 1000, 2048, 4096, 10000];

/// Compute the number of parallel elements for MSM throughput benchmarks.
/// Uses aggressive values to maximize throughput testing while keeping setup time reasonable.
fn msm_throughput_elements(input_size: usize) -> u64 {
    match input_size {
        n if n <= 1000 => 64,
        n if n <= 4096 => 32,
        _ => 16,
    }
}

fn generate_scalars(rng: &mut StdRng, n: usize) -> Vec<Zp> {
    (0..n).map(|_| Zp::rand(rng)).collect()
}

// =============================================================================
// Trait abstracting over G1/G2 for MSM benchmarks.
//
// Each curve subgroup has different affine types, MSM entry points, and label
// strings. This trait captures those differences so the CPU and GPU benchmark
// bodies are written once as generic functions, eliminating the duplication
// between G1 and G2 variants.
// =============================================================================

trait MsmBenchGroup {
    type Affine: Send + Sync;

    const MSM_ID: MsmBench;

    fn generate_points(rng: &mut StdRng, n: usize) -> Vec<Self::Affine>;
    fn cpu_msm(bases: &[Self::Affine], scalars: &[Zp]);
    #[cfg(feature = "gpu-zk")]
    fn gpu_msm(bases: &[Self::Affine], scalars: &[Zp], gpu_index: u32);
}

struct G1Bench;

impl MsmBenchGroup for G1Bench {
    type Affine = G1Affine;

    const MSM_ID: MsmBench = MsmBench::G1(MsmFlavor::Bls12_446);

    fn generate_points(rng: &mut StdRng, n: usize) -> Vec<G1Affine> {
        (0..n)
            .map(|_| {
                let point = G1::GENERATOR.mul_scalar(Zp::rand(rng));
                point.normalize()
            })
            .collect()
    }

    fn cpu_msm(bases: &[G1Affine], scalars: &[Zp]) {
        black_box(G1Affine::multi_mul_scalar(
            black_box(bases),
            black_box(scalars),
        ));
    }

    #[cfg(feature = "gpu-zk")]
    fn gpu_msm(bases: &[G1Affine], scalars: &[Zp], gpu_index: u32) {
        use tfhe_zk_pok::gpu::g1_msm_gpu;
        black_box(g1_msm_gpu(black_box(bases), black_box(scalars), gpu_index));
    }
}

struct G2Bench;

impl MsmBenchGroup for G2Bench {
    type Affine = G2Affine;

    const MSM_ID: MsmBench = MsmBench::G2(MsmFlavor::Bls12_446);

    fn generate_points(rng: &mut StdRng, n: usize) -> Vec<G2Affine> {
        (0..n)
            .map(|_| {
                let point = G2::GENERATOR.mul_scalar(Zp::rand(rng));
                point.normalize()
            })
            .collect()
    }

    fn cpu_msm(bases: &[G2Affine], scalars: &[Zp]) {
        black_box(G2Affine::multi_mul_scalar(
            black_box(bases),
            black_box(scalars),
        ));
    }

    #[cfg(feature = "gpu-zk")]
    fn gpu_msm(bases: &[G2Affine], scalars: &[Zp], gpu_index: u32) {
        use tfhe_zk_pok::gpu::g2_msm_gpu;
        black_box(g2_msm_gpu(black_box(bases), black_box(scalars), gpu_index));
    }
}

// =============================================================================
// Generic benchmark functions parameterized by MsmBenchGroup
// =============================================================================

fn bench_cpu_msm<T: MsmBenchGroup>(c: &mut Criterion) {
    let group_name =
        BenchmarkSpec::<str>::new_zk_msm(T::MSM_ID, Backend::Cpu, *get_bench_type(), None);
    let mut group = c.benchmark_group(group_name.to_string());
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    for size in MSM_SIZES.iter() {
        let n = *size;
        let bench_id =
            BenchmarkSpec::<str>::new_zk_msm(T::MSM_ID, Backend::Cpu, *get_bench_type(), Some(n));
        let bench_id_string = bench_id.to_string();

        match get_bench_type() {
            BenchmarkType::Latency => {
                let mut rng = StdRng::seed_from_u64(42);
                let bases = T::generate_points(&mut rng, n);
                let scalars = generate_scalars(&mut rng, n);

                group.bench_with_input(&bench_id_string, &n, |b, _| {
                    b.iter(|| T::cpu_msm(&bases, &scalars));
                });
            }
            BenchmarkType::Throughput => {
                let elements = msm_throughput_elements(n);
                group.throughput(Throughput::Elements(elements));

                group.bench_with_input(&bench_id_string, &n, |b, _| {
                    // Setup generates test data in parallel, excluded from measurement
                    let setup = || {
                        (0..elements)
                            .into_par_iter()
                            .map(|i| {
                                let mut rng = StdRng::seed_from_u64(42 + i);
                                let bases = T::generate_points(&mut rng, n);
                                let scalars = generate_scalars(&mut rng, n);
                                (bases, scalars)
                            })
                            .collect::<Vec<_>>()
                    };

                    b.iter_batched(
                        setup,
                        |test_data| {
                            test_data.par_iter().for_each(|(bases, scalars)| {
                                T::cpu_msm(bases, scalars);
                            });
                        },
                        BatchSize::LargeInput,
                    );
                });
            }
        }

        write_to_json(
            &bench_id,
            T::MSM_ID.display_name(),
            &OperatorType::Atomic,
            64,     // bit_size for curve scalar operations
            vec![], // decomposition_basis not applicable for MSM
        );
    }
    group.finish();
}

#[cfg(feature = "gpu-zk")]
fn bench_gpu_msm<T: MsmBenchGroup>(c: &mut Criterion) {
    use tfhe_zk_pok::gpu::select_gpu_for_msm;

    let group_name =
        BenchmarkSpec::<str>::new_zk_msm(T::MSM_ID, Backend::Cuda, *get_bench_type(), None);
    let mut group = c.benchmark_group(&group_name.to_string());
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    // Resolve GPU index once — stream creation/destruction is handled inside the MSM calls
    let gpu_index = select_gpu_for_msm();

    for size in MSM_SIZES.iter() {
        let n = *size;
        let bench_id =
            BenchmarkSpec::<str>::new_zk_msm(T::MSM_ID, Backend::Cuda, *get_bench_type(), Some(n));
        let bench_id_string = bench_id.to_string();

        match get_bench_type() {
            BenchmarkType::Latency => {
                let mut rng = StdRng::seed_from_u64(42);
                let bases = T::generate_points(&mut rng, n);
                let scalars = generate_scalars(&mut rng, n);

                group.bench_with_input(&bench_id_string, &n, |b, _| {
                    b.iter(|| T::gpu_msm(&bases, &scalars, gpu_index));
                });
            }
            BenchmarkType::Throughput => {
                let elements = msm_throughput_elements(n);
                group.throughput(Throughput::Elements(elements));

                group.bench_with_input(&bench_id_string, &n, |b, _| {
                    let setup = || {
                        (0..elements)
                            .into_par_iter()
                            .map(|i| {
                                let mut rng = StdRng::seed_from_u64(42 + i);
                                let bases = T::generate_points(&mut rng, n);
                                let scalars = generate_scalars(&mut rng, n);
                                (bases, scalars)
                            })
                            .collect::<Vec<_>>()
                    };

                    b.iter_batched(
                        setup,
                        |test_data| {
                            test_data.par_iter().for_each(|(bases, scalars)| {
                                T::gpu_msm(bases, scalars, gpu_index);
                            });
                        },
                        BatchSize::LargeInput,
                    );
                });
            }
        }

        write_to_json(
            &bench_id,
            format!("{}_CUDA", T::MSM_ID.display_name()),
            &OperatorType::Atomic,
            64,     // bit_size for curve scalar operations
            vec![], // decomposition_basis not applicable for MSM
        );
    }
    group.finish();
}

// =============================================================================
// Thin wrappers: criterion_group! requires concrete function names, so these
// delegate to the generic implementations with the appropriate type parameter.
// =============================================================================

fn bench_cpu_g1_msm(c: &mut Criterion) {
    bench_cpu_msm::<G1Bench>(c);
}

fn bench_cpu_g2_msm(c: &mut Criterion) {
    bench_cpu_msm::<G2Bench>(c);
}

#[cfg(feature = "gpu-zk")]
fn bench_gpu_g1_msm(c: &mut Criterion) {
    bench_gpu_msm::<G1Bench>(c);
}

#[cfg(feature = "gpu-zk")]
fn bench_gpu_g2_msm(c: &mut Criterion) {
    bench_gpu_msm::<G2Bench>(c);
}

criterion_group!(benches_cpu, bench_cpu_g1_msm, bench_cpu_g2_msm,);

#[cfg(feature = "gpu-zk")]
criterion_group!(benches_gpu, bench_gpu_g1_msm, bench_gpu_g2_msm,);

#[cfg(feature = "gpu-zk")]
criterion_main!(benches_cpu, benches_gpu);

#[cfg(not(feature = "gpu-zk"))]
criterion_main!(benches_cpu);

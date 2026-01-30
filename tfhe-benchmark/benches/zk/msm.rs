//! Benchmark comparing CPU MSM vs GPU MSM using tfhe-zk-pok entry points
//!
//! This benchmark measures the performance of multi-scalar multiplication (MSM)
//! for both G1 and G2 points on the BLS12-446 curve.
//!
//! Both CPU and GPU benchmarks use the same entry points (`G1Affine::multi_mul_scalar`,
//! `G2Affine::multi_mul_scalar`). The `experimental-gpu-zk` feature flag automatically routes to
//! GPU internally when enabled.
//!
//! ## Running the benchmarks
//!
//! ```bash
//! # CPU only
//! cargo bench --package tfhe-benchmark --bench zk-msm
//!
//! # CPU and GPU
//! cargo bench --package tfhe-benchmark --bench zk-msm --features experimental-gpu-zk
//! ```

use benchmark::utilities::{
    get_bench_type, write_to_json, BenchmarkType, CryptoParametersRecord, OperatorType,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::time::Duration;

use tfhe_zk_pok::curve_api::bls12_446::{G1Affine, G2Affine, Zp, G1, G2};
use tfhe_zk_pok::curve_api::CurveGroupOps;

/// Generate random G1 affine points using tfhe-zk-pok
fn generate_g1_affine_points(rng: &mut StdRng, n: usize) -> Vec<G1Affine> {
    (0..n)
        .map(|_| {
            let point = G1::GENERATOR.mul_scalar(Zp::rand(rng));
            point.normalize()
        })
        .collect()
}

/// Generate random G2 affine points using tfhe-zk-pok
fn generate_g2_affine_points(rng: &mut StdRng, n: usize) -> Vec<G2Affine> {
    (0..n)
        .map(|_| {
            let point = G2::GENERATOR.mul_scalar(Zp::rand(rng));
            point.normalize()
        })
        .collect()
}

/// Generate random scalars using tfhe-zk-pok
fn generate_scalars(rng: &mut StdRng, n: usize) -> Vec<Zp> {
    (0..n).map(|_| Zp::rand(rng)).collect()
}

/// Benchmark CPU MSM for G1 points using tfhe-zk-pok entry points
fn bench_cpu_g1_msm(c: &mut Criterion) {
    // Skip benchmarks entirely if throughput mode is selected (disabled - too slow)
    if matches!(get_bench_type(), BenchmarkType::Throughput) {
        return;
    }

    let curve_name = "bls12_446";
    let subgroup_name = "G1";
    let bench_name = format!("zk::msm::{curve_name}::{subgroup_name}");

    let mut group = c.benchmark_group(&bench_name);
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    for size in [100, 1000, 2048, 4096, 10000].iter() {
        let n = *size;
        let mut rng = StdRng::seed_from_u64(42);

        // Generate test data using tfhe-zk-pok types
        let bases = generate_g1_affine_points(&mut rng, n);
        let scalars = generate_scalars(&mut rng, n);

        let bench_id;
        let bench_shortname = "zk::msm::bls12_446::g1";

        match get_bench_type() {
            BenchmarkType::Latency => {
                bench_id = format!("{bench_name}::{n}");
                group.bench_with_input(&bench_id, &n, |b, _| {
                    b.iter(|| {
                        let result =
                            G1Affine::multi_mul_scalar(black_box(&bases), black_box(&scalars));
                        black_box(result)
                    });
                });
            }
            BenchmarkType::Throughput => {
                // Throughput mode disabled - too slow
                // Benchmarks are skipped when this mode is selected (see early return above)
                // This branch is unreachable due to early return, but kept for code visibility
                // To re-enable: uncomment the code below and remove the early return
                /*
                use criterion::Throughput;
                use rayon::prelude::*;

                let elements = rayon::current_num_threads() as u64;
                group.throughput(Throughput::Elements(elements));

                // Generate multiple sets of test data for parallel execution
                let test_data: Vec<_> = (0..elements)
                    .map(|i| {
                        let mut rng = StdRng::seed_from_u64(42 + i);
                        let bases = generate_g1_affine_points(&mut rng, n);
                        let scalars = generate_scalars(&mut rng, n);
                        (bases, scalars)
                    })
                    .collect();

                bench_id = format!("{bench_name}::throughput::{n}");
                group.bench_with_input(&bench_id, &n, |b, _| {
                    b.iter(|| {
                        test_data.par_iter().for_each(|(bases, scalars)| {
                            let result =
                                G1Affine::multi_mul_scalar(black_box(bases), black_box(scalars));
                            black_box(result);
                        });
                    });
                });
                */
                unreachable!(
                    "Throughput mode is disabled - early return should prevent reaching here"
                );
            }
        }

        // MSM benchmarks are curve operations, use minimal parameters
        let params: CryptoParametersRecord<u64> = CryptoParametersRecord::default();
        write_to_json(
            &bench_id,
            params,
            "MSM_BLS12_446_G1",
            bench_shortname,
            &OperatorType::Atomic,
            64,     // bit_size for curve scalar operations
            vec![], // decomposition_basis not applicable for MSM
        );
    }
    group.finish();
}

/// Benchmark CPU MSM for G2 points using tfhe-zk-pok entry points
fn bench_cpu_g2_msm(c: &mut Criterion) {
    // Skip benchmarks entirely if throughput mode is selected (disabled - too slow)
    if matches!(get_bench_type(), BenchmarkType::Throughput) {
        return;
    }

    let curve_name = "bls12_446";
    let subgroup_name = "G2";
    let bench_name = format!("zk::msm::{curve_name}::{subgroup_name}");

    let mut group = c.benchmark_group(&bench_name);
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    for size in [100, 1000, 2048, 4096, 10000].iter() {
        let n = *size;
        let mut rng = StdRng::seed_from_u64(42);

        // Generate test data using tfhe-zk-pok types
        let bases = generate_g2_affine_points(&mut rng, n);
        let scalars = generate_scalars(&mut rng, n);

        let bench_id;
        let bench_shortname = "zk::msm::bls12_446::g2";

        match get_bench_type() {
            BenchmarkType::Latency => {
                bench_id = format!("{bench_name}::{n}");
                group.bench_with_input(&bench_id, &n, |b, _| {
                    b.iter(|| {
                        let result =
                            G2Affine::multi_mul_scalar(black_box(&bases), black_box(&scalars));
                        black_box(result)
                    });
                });
            }
            BenchmarkType::Throughput => {
                // Throughput mode disabled - too slow
                // Benchmarks are skipped when this mode is selected (see early return above)
                // This branch is unreachable due to early return, but kept for code visibility
                // To re-enable: uncomment the code below and remove the early return
                /*
                use criterion::Throughput;
                use rayon::prelude::*;

                let elements = rayon::current_num_threads() as u64;
                group.throughput(Throughput::Elements(elements));

                // Generate multiple sets of test data for parallel execution
                let test_data: Vec<_> = (0..elements)
                    .map(|i| {
                        let mut rng = StdRng::seed_from_u64(42 + i);
                        let bases = generate_g2_affine_points(&mut rng, n);
                        let scalars = generate_scalars(&mut rng, n);
                        (bases, scalars)
                    })
                    .collect();

                bench_id = format!("{bench_name}::throughput::{n}");
                group.bench_with_input(&bench_id, &n, |b, _| {
                    b.iter(|| {
                        test_data.par_iter().for_each(|(bases, scalars)| {
                            let result =
                                G2Affine::multi_mul_scalar(black_box(bases), black_box(scalars));
                            black_box(result);
                        });
                    });
                });
                */
                unreachable!(
                    "Throughput mode is disabled - early return should prevent reaching here"
                );
            }
        }

        // MSM benchmarks are curve operations, use minimal parameters
        let params: CryptoParametersRecord<u64> = CryptoParametersRecord::default();
        write_to_json(
            &bench_id,
            params,
            "MSM_BLS12_446_G2",
            bench_shortname,
            &OperatorType::Atomic,
            64,     // bit_size for curve scalar operations
            vec![], // decomposition_basis not applicable for MSM
        );
    }
    group.finish();
}

/// Benchmark GPU MSM for G1 points using tfhe-zk-pok entry points
#[cfg(feature = "experimental-gpu-zk")]
fn bench_gpu_g1_msm(c: &mut Criterion) {
    // Skip benchmarks entirely if throughput mode is selected (disabled - too slow)
    if matches!(get_bench_type(), BenchmarkType::Throughput) {
        return;
    }

    let curve_name = "bls12_446";
    let subgroup_name = "G1";
    let bench_name = format!("zk::cuda::msm::{curve_name}::{subgroup_name}");

    let mut group = c.benchmark_group(&bench_name);
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    for size in [100, 1000, 2048, 4096, 10000].iter() {
        let n = *size;
        let mut rng = StdRng::seed_from_u64(42);

        // Generate test data using tfhe-zk-pok types
        let bases = generate_g1_affine_points(&mut rng, n);
        let scalars = generate_scalars(&mut rng, n);

        let bench_id;
        let bench_shortname = "zk::cuda::msm::bls12_446::g1";

        match get_bench_type() {
            BenchmarkType::Latency => {
                bench_id = format!("{bench_name}::{n}");
                group.bench_with_input(&bench_id, &n, |b, _| {
                    b.iter(|| {
                        // Uses the same entry point - GPU routing happens internally
                        let result =
                            G1Affine::multi_mul_scalar(black_box(&bases), black_box(&scalars));
                        black_box(result)
                    });
                });
            }
            BenchmarkType::Throughput => {
                // Throughput mode disabled - too slow
                // Benchmarks are skipped when this mode is selected (see early return above)
                // This branch is unreachable due to early return, but kept for code visibility
                // To re-enable: uncomment the code below and remove the early return
                /*
                use criterion::Throughput;
                use rayon::prelude::*;

                let elements = rayon::current_num_threads() as u64;
                group.throughput(Throughput::Elements(elements));

                // Generate multiple sets of test data for parallel execution
                let test_data: Vec<_> = (0..elements)
                    .map(|i| {
                        let mut rng = StdRng::seed_from_u64(42 + i);
                        let bases = generate_g1_affine_points(&mut rng, n);
                        let scalars = generate_scalars(&mut rng, n);
                        (bases, scalars)
                    })
                    .collect();

                bench_id = format!("{bench_name}::throughput::{n}");
                group.bench_with_input(&bench_id, &n, |b, _| {
                    b.iter(|| {
                        // Uses the same entry point - GPU routing happens internally
                        test_data.par_iter().for_each(|(bases, scalars)| {
                            let result =
                                G1Affine::multi_mul_scalar(black_box(bases), black_box(scalars));
                            black_box(result);
                        });
                    });
                });
                */
                unreachable!(
                    "Throughput mode is disabled - early return should prevent reaching here"
                );
            }
        }

        // MSM benchmarks are curve operations, use minimal parameters
        let params: CryptoParametersRecord<u64> = CryptoParametersRecord::default();
        write_to_json(
            &bench_id,
            params,
            "MSM_BLS12_446_G1_CUDA",
            bench_shortname,
            &OperatorType::Atomic,
            64,     // bit_size for curve scalar operations
            vec![], // decomposition_basis not applicable for MSM
        );
    }
    group.finish();
}

/// Benchmark GPU MSM for G2 points using tfhe-zk-pok entry points
#[cfg(feature = "experimental-gpu-zk")]
fn bench_gpu_g2_msm(c: &mut Criterion) {
    // Skip benchmarks entirely if throughput mode is selected (disabled - too slow)
    if matches!(get_bench_type(), BenchmarkType::Throughput) {
        return;
    }

    let curve_name = "bls12_446";
    let subgroup_name = "G2";
    let bench_name = format!("zk::cuda::msm::{curve_name}::{subgroup_name}");

    let mut group = c.benchmark_group(&bench_name);
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(30));

    for size in [100, 1000, 2048, 4096, 10000].iter() {
        let n = *size;
        let mut rng = StdRng::seed_from_u64(42);

        // Generate test data using tfhe-zk-pok types
        let bases = generate_g2_affine_points(&mut rng, n);
        let scalars = generate_scalars(&mut rng, n);

        let bench_id;
        let bench_shortname = "zk::cuda::msm::bls12_446::g2";

        match get_bench_type() {
            BenchmarkType::Latency => {
                bench_id = format!("{bench_name}::{n}");
                group.bench_with_input(&bench_id, &n, |b, _| {
                    b.iter(|| {
                        // Uses the same entry point - GPU routing happens internally
                        let result =
                            G2Affine::multi_mul_scalar(black_box(&bases), black_box(&scalars));
                        black_box(result)
                    });
                });
            }
            BenchmarkType::Throughput => {
                // Throughput mode disabled - too slow
                // Benchmarks are skipped when this mode is selected (see early return above)
                // This branch is unreachable due to early return, but kept for code visibility
                // To re-enable: uncomment the code below and remove the early return
                /*
                use criterion::Throughput;
                use rayon::prelude::*;

                let elements = rayon::current_num_threads() as u64;
                group.throughput(Throughput::Elements(elements));

                // Generate multiple sets of test data for parallel execution
                let test_data: Vec<_> = (0..elements)
                    .map(|i| {
                        let mut rng = StdRng::seed_from_u64(42 + i);
                        let bases = generate_g2_affine_points(&mut rng, n);
                        let scalars = generate_scalars(&mut rng, n);
                        (bases, scalars)
                    })
                    .collect();

                bench_id = format!("{bench_name}::throughput::{n}");
                group.bench_with_input(&bench_id, &n, |b, _| {
                    b.iter(|| {
                        // Uses the same entry point - GPU routing happens internally
                        test_data.par_iter().for_each(|(bases, scalars)| {
                            let result =
                                G2Affine::multi_mul_scalar(black_box(bases), black_box(scalars));
                            black_box(result);
                        });
                    });
                });
                */
                unreachable!(
                    "Throughput mode is disabled - early return should prevent reaching here"
                );
            }
        }

        // MSM benchmarks are curve operations, use minimal parameters
        let params: CryptoParametersRecord<u64> = CryptoParametersRecord::default();
        write_to_json(
            &bench_id,
            params,
            "MSM_BLS12_446_G2_CUDA",
            bench_shortname,
            &OperatorType::Atomic,
            64,     // bit_size for curve scalar operations
            vec![], // decomposition_basis not applicable for MSM
        );
    }
    group.finish();
}

// CPU benchmarks (always available)
criterion_group!(benches_cpu, bench_cpu_g1_msm, bench_cpu_g2_msm,);

// GPU benchmarks (only when GPU feature is enabled)
#[cfg(feature = "experimental-gpu-zk")]
criterion_group!(benches_gpu, bench_gpu_g1_msm, bench_gpu_g2_msm,);

// Conditionally include GPU benchmarks in main
#[cfg(feature = "experimental-gpu-zk")]
criterion_main!(benches_cpu, benches_gpu);

#[cfg(not(feature = "experimental-gpu-zk"))]
criterion_main!(benches_cpu);

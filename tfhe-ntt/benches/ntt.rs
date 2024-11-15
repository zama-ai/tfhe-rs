use serde::Serialize;
use std::{fs, path::PathBuf};

use criterion::*;
use tfhe_ntt::{prime::largest_prime_in_arithmetic_progression64, *};

#[derive(Serialize)]
enum PrimeModulus {
    // 32 bits section
    FitsIn30Bits,
    FitsIn31Bits,
    FitsIn32Bits,
    Native32,
    // 64 bits section
    FitsIn50Bits,
    FitsIn51Bits,
    FitsIn52Bits,
    FitsIn62Bits,
    FitsIn63Bits,
    FitsIn64Bits,
    Native64,
    // 128 bits section
    Native128,
}

impl PrimeModulus {
    fn from_u64(p: u64) -> Self {
        if p < 1 << 30 {
            Self::FitsIn30Bits
        } else if p < 1 << 31 {
            Self::FitsIn31Bits
        } else if p < 1 << 32 {
            Self::FitsIn32Bits
        } else if p < 1 << 50 {
            Self::FitsIn50Bits
        } else if p < 1 << 51 {
            Self::FitsIn51Bits
        } else if p < 1 << 52 {
            Self::FitsIn52Bits
        } else if p < 1 << 62 {
            Self::FitsIn62Bits
        } else if p < 1 << 63 {
            Self::FitsIn63Bits
        } else {
            Self::FitsIn64Bits
        }
    }
}

#[derive(Serialize)]
struct BenchmarkParametersRecord {
    display_name: String,
    polynomial_size: usize,
    prime_modulus: PrimeModulus,
    // If this field value is set to 0 means that the number is not a prime.
    prime_number: u64,
}

/// Writes benchmarks parameters to disk in JSON format.
fn write_to_json(
    bench_id: &str,
    display_name: impl Into<String>,
    polynomial_size: usize,
    prime_modulus: PrimeModulus,
    prime_number: u64,
) {
    let record = BenchmarkParametersRecord {
        display_name: display_name.into(),
        polynomial_size,
        prime_modulus,
        prime_number,
    };

    let mut params_directory = ["benchmarks_parameters", bench_id]
        .iter()
        .collect::<PathBuf>();
    fs::create_dir_all(&params_directory).unwrap();
    params_directory.push("parameters.json");

    fs::write(params_directory, serde_json::to_string(&record).unwrap()).unwrap();
}

fn criterion_bench(c: &mut Criterion) {
    let ns = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768];
    for n in ns {
        let mut data = vec![0; n];
        for p in [
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 29, 1 << 30).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 30, 1 << 31).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 31, 1 << 32).unwrap(),
        ] {
            let p_u64 = p;
            let p = p as u32;
            let plan = prime32::Plan::try_new(n, p).unwrap();
            let bench_id = format!("fwd-32-{p}-{n}");
            c.bench_function(&bench_id, |b| {
                b.iter(|| plan.fwd(&mut data));
            });
            write_to_json(&bench_id, "fwd-32", n, PrimeModulus::from_u64(p_u64), p_u64);

            let bench_id = format!("inv-32-{p}-{n}");
            c.bench_function(&bench_id, |b| {
                b.iter(|| plan.inv(&mut data));
            });
            write_to_json(&bench_id, "inv-32", n, PrimeModulus::from_u64(p_u64), p_u64);
        }
    }

    for n in ns {
        let mut data = vec![0; n];
        for p in [
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 49, 1 << 50).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 50, 1 << 51).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 61, 1 << 62).unwrap(),
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 62, 1 << 63).unwrap(),
            prime64::Solinas::P,
            largest_prime_in_arithmetic_progression64(1 << 16, 1, 1 << 63, u64::MAX).unwrap(),
        ] {
            let plan = prime64::Plan::try_new(n, p).unwrap();
            let bench_id = format!("fwd-64-{p}-{n}");
            c.bench_function(&bench_id, |b| {
                b.iter(|| plan.fwd(&mut data));
            });
            write_to_json(&bench_id, "fwd-64", n, PrimeModulus::from_u64(p), p);

            let bench_id = format!("inv-64-{p}-{n}");
            c.bench_function(&bench_id, |b| {
                b.iter(|| plan.inv(&mut data));
            });
            write_to_json(&bench_id, "inv-64", n, PrimeModulus::from_u64(p), p);
        }
    }

    for n in ns {
        let mut prod = vec![0; n];
        let lhs = vec![0; n];
        let rhs = vec![0; n];

        let plan = native32::Plan32::try_new(n).unwrap();
        let bench_id = format!("native32-32-{n}");
        c.bench_function(&bench_id, |b| {
            b.iter(|| plan.negacyclic_polymul(&mut prod, &lhs, &rhs));
        });
        write_to_json(&bench_id, "native32-32", n, PrimeModulus::Native32, 0);

        let plan = native_binary32::Plan32::try_new(n).unwrap();
        let bench_id = format!("nativebinary32-32-{n}");
        c.bench_function(&bench_id, |b| {
            b.iter(|| plan.negacyclic_polymul(&mut prod, &lhs, &rhs));
        });
        write_to_json(&bench_id, "nativebinary32-32", n, PrimeModulus::Native32, 0);

        #[cfg(all(feature = "nightly", any(target_arch = "x86", target_arch = "x86_64")))]
        {
            if let Some(plan) = native32::Plan52::try_new(n) {
                let bench_id = format!("native32-52-{n}");
                c.bench_function(&bench_id, |b| {
                    b.iter(|| plan.negacyclic_polymul(&mut prod, &lhs, &rhs));
                });
                write_to_json(&bench_id, "native32-52", n, PrimeModulus::Native32, 0);
            }
            if let Some(plan) = native_binary32::Plan52::try_new(n) {
                let bench_id = format!("nativebinary32-52-{n}");
                c.bench_function(&bench_id, |b| {
                    b.iter(|| plan.negacyclic_polymul(&mut prod, &lhs, &rhs));
                });
                write_to_json(&bench_id, "nativebinary32-52", n, PrimeModulus::Native32, 0);
            }
        }
    }

    for n in ns {
        let mut prod = vec![0; n];
        let lhs = vec![0; n];
        let rhs = vec![0; n];

        let plan = native64::Plan32::try_new(n).unwrap();
        let bench_id = format!("native64-32-{n}");
        c.bench_function(&bench_id, |b| {
            b.iter(|| plan.negacyclic_polymul(&mut prod, &lhs, &rhs));
        });
        write_to_json(&bench_id, "native64-32", n, PrimeModulus::Native64, 0);

        let plan = native_binary64::Plan32::try_new(n).unwrap();
        let bench_id = format!("nativebinary64-32-{n}");
        c.bench_function(&bench_id, |b| {
            b.iter(|| plan.negacyclic_polymul(&mut prod, &lhs, &rhs));
        });
        write_to_json(&bench_id, "nativebinary64-32", n, PrimeModulus::Native64, 0);

        #[cfg(all(feature = "nightly", any(target_arch = "x86", target_arch = "x86_64")))]
        {
            if let Some(plan) = native64::Plan52::try_new(n) {
                let bench_id = format!("native64-52-{n}");
                c.bench_function(&bench_id, |b| {
                    b.iter(|| plan.negacyclic_polymul(&mut prod, &lhs, &rhs));
                });
                write_to_json(&bench_id, "native64-52", n, PrimeModulus::Native64, 0);
            }
            if let Some(plan) = native_binary64::Plan52::try_new(n) {
                let bench_id = format!("nativebinary64-52-{n}");
                c.bench_function(&bench_id, |b| {
                    b.iter(|| plan.negacyclic_polymul(&mut prod, &lhs, &rhs));
                });
                write_to_json(&bench_id, "nativebinary64-52", n, PrimeModulus::Native64, 0);
            }
        }
    }

    for n in ns {
        let mut prod = vec![0; n];
        let lhs = vec![0; n];
        let rhs = vec![0; n];

        let plan = native128::Plan32::try_new(n).unwrap();
        let bench_id = format!("native128-32-{n}");
        c.bench_function(&bench_id, |b| {
            b.iter(|| plan.negacyclic_polymul(&mut prod, &lhs, &rhs));
        });
        write_to_json(&bench_id, "native128-32", n, PrimeModulus::Native128, 0);

        let plan = native_binary128::Plan32::try_new(n).unwrap();
        let bench_id = format!("nativebinary128-32-{n}");
        c.bench_function(&bench_id, |b| {
            b.iter(|| plan.negacyclic_polymul(&mut prod, &lhs, &rhs));
        });
        write_to_json(
            &bench_id,
            "nativebinary128-32",
            n,
            PrimeModulus::Native128,
            0,
        );
    }
}

criterion_group!(benches, criterion_bench);
criterion_main!(benches);

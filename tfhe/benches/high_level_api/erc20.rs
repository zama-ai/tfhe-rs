#[path = "../utilities.rs"]
mod utilities;

use crate::utilities::{write_to_json, OperatorType};
use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion, Throughput};
use rand::prelude::*;
use rand::thread_rng;
use rayon::prelude::*;
use std::ops::{Add, Mul, Sub};
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
use tfhe::shortint::parameters::*;
use tfhe::{set_server_key, ClientKey, CompressedServerKey, ConfigBuilder, FheBool, FheUint64};

/// Transfer as written in the original FHEvm white-paper,
/// it uses a comparison to check if the sender has enough,
/// and cmuxes based on the comparison result
fn transfer_whitepaper<FheType>(
    from_amount: &FheType,
    to_amount: &FheType,
    amount: &FheType,
) -> (FheType, FheType)
where
    FheType: Add<Output = FheType> + for<'a> FheOrd<&'a FheType>,
    FheBool: IfThenElse<FheType>,
    for<'a> &'a FheType: Add<Output = FheType> + Sub<Output = FheType>,
{
    let has_enough_funds = (from_amount).ge(amount);

    let mut new_to_amount = to_amount + amount;
    new_to_amount = has_enough_funds.if_then_else(&new_to_amount, to_amount);

    let mut new_from_amount = from_amount - amount;
    new_from_amount = has_enough_funds.if_then_else(&new_from_amount, from_amount);

    (new_from_amount, new_to_amount)
}

/// This one also uses a comparison, but it leverages the 'boolean' multiplication
/// instead of cmuxes, so it is faster
fn transfer_no_cmux<FheType>(
    from_amount: &FheType,
    to_amount: &FheType,
    amount: &FheType,
) -> (FheType, FheType)
where
    FheType: Add<Output = FheType> + CastFrom<FheBool> + for<'a> FheOrd<&'a FheType>,
    FheBool: IfThenElse<FheType>,
    for<'a> &'a FheType:
        Add<Output = FheType> + Sub<Output = FheType> + Mul<FheType, Output = FheType>,
{
    let has_enough_funds = (from_amount).ge(amount);

    let amount = amount * FheType::cast_from(has_enough_funds);

    let new_to_amount = to_amount + &amount;
    let new_from_amount = from_amount - &amount;

    (new_from_amount, new_to_amount)
}

/// This one uses overflowing sub to remove the need for comparison
/// it also uses the 'boolean' multiplication
fn transfer_overflow<FheType>(
    from_amount: &FheType,
    to_amount: &FheType,
    amount: &FheType,
) -> (FheType, FheType)
where
    FheType: CastFrom<FheBool> + for<'a> FheOrd<&'a FheType>,
    FheBool: IfThenElse<FheType>,
    for<'a> &'a FheType: Add<FheType, Output = FheType>
        + OverflowingSub<&'a FheType, Output = FheType>
        + Mul<FheType, Output = FheType>,
{
    let (new_from, did_not_have_enough) = (from_amount).overflowing_sub(amount);

    let new_from_amount = did_not_have_enough.if_then_else(from_amount, &new_from);

    let had_enough_funds = !did_not_have_enough;
    let new_to_amount = to_amount + (amount * FheType::cast_from(had_enough_funds));

    (new_from_amount, new_to_amount)
}

/// This ones uses both overflowing_add/sub to check that both
/// the sender has enough funds, and the receiver will not overflow its balance
fn transfer_safe<FheType>(
    from_amount: &FheType,
    to_amount: &FheType,
    amount: &FheType,
) -> (FheType, FheType)
where
    for<'a> &'a FheType: OverflowingSub<&'a FheType, Output = FheType>
        + OverflowingAdd<&'a FheType, Output = FheType>,
    FheBool: IfThenElse<FheType>,
{
    let (new_from, did_not_have_enough_funds) = (from_amount).overflowing_sub(amount);
    let (new_to, did_not_have_enough_space) = (to_amount).overflowing_add(amount);

    let something_not_ok = did_not_have_enough_funds | did_not_have_enough_space;

    let new_from_amount = something_not_ok.if_then_else(from_amount, &new_from);
    let new_to_amount = something_not_ok.if_then_else(to_amount, &new_to);

    (new_from_amount, new_to_amount)
}

#[cfg(feature = "pbs-stats")]
mod pbs_stats {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::path::Path;

    fn write_result(file: &mut File, name: &str, value: usize) {
        let line = format!("{name},{value}\n");
        let error_message = format!("cannot write {name} result into file");
        file.write_all(line.as_bytes()).expect(&error_message);
    }

    pub fn print_transfer_pbs_counts<FheType, F>(
        client_key: &ClientKey,
        type_name: &str,
        fn_name: &str,
        transfer_func: F,
    ) where
        FheType: FheEncrypt<u64, ClientKey>,
        F: for<'a> Fn(&'a FheType, &'a FheType, &'a FheType) -> (FheType, FheType),
    {
        let mut rng = thread_rng();

        let from_amount = FheType::encrypt(rng.gen::<u64>(), client_key);
        let to_amount = FheType::encrypt(rng.gen::<u64>(), client_key);
        let amount = FheType::encrypt(rng.gen::<u64>(), client_key);

        tfhe::reset_pbs_count();
        let (_, _) = transfer_func(&from_amount, &to_amount, &amount);
        let count = tfhe::get_pbs_count();

        println!("ERC20 transfer/{fn_name}::{type_name}: {count} PBS");

        let params = client_key.computation_parameters();

        let test_name = if cfg!(feature = "gpu") {
            format!("hlapi::cuda::erc20::pbs_count::{fn_name}::{type_name}")
        } else {
            format!("hlapi::erc20::pbs_count::{fn_name}::{type_name}")
        };

        let results_file = Path::new("erc20_pbs_count.csv");
        if !results_file.exists() {
            File::create(results_file).expect("create results file failed");
        }
        let mut file = OpenOptions::new()
            .append(true)
            .open(results_file)
            .expect("cannot open results file");

        write_result(&mut file, &test_name, count as usize);

        write_to_json::<u64, _>(
            &test_name,
            params,
            params.name(),
            "pbs-count",
            &OperatorType::Atomic,
            0,
            vec![],
        );
    }
}

fn bench_transfer_latency<FheType, F>(
    c: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    bench_name: &str,
    type_name: &str,
    fn_name: &str,
    transfer_func: F,
) where
    FheType: FheEncrypt<u64, ClientKey>,
    F: for<'a> Fn(&'a FheType, &'a FheType, &'a FheType) -> (FheType, FheType),
{
    let bench_id = format!("{bench_name}::{fn_name}::{type_name}");
    c.bench_function(&bench_id, |b| {
        let mut rng = thread_rng();

        let from_amount = FheType::encrypt(rng.gen::<u64>(), client_key);
        let to_amount = FheType::encrypt(rng.gen::<u64>(), client_key);
        let amount = FheType::encrypt(rng.gen::<u64>(), client_key);

        b.iter(|| {
            let (_, _) = transfer_func(&from_amount, &to_amount, &amount);
        })
    });

    let params = client_key.computation_parameters();

    write_to_json::<u64, _>(
        &bench_id,
        params,
        params.name(),
        "erc20-transfer",
        &OperatorType::Atomic,
        64,
        vec![],
    );
}

fn bench_transfer_throughput<FheType, F>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    bench_name: &str,
    type_name: &str,
    fn_name: &str,
    transfer_func: F,
) where
    FheType: FheEncrypt<u64, ClientKey> + Send + Sync,
    F: for<'a> Fn(&'a FheType, &'a FheType, &'a FheType) -> (FheType, FheType) + Sync,
{
    let mut rng = thread_rng();
    #[cfg(not(feature = "gpu"))]
    let num_gpus = 1u64;
    #[cfg(feature = "gpu")]
    let num_gpus = unsafe { cuda_get_number_of_gpus() } as u64;

    for num_elems in [10 * num_gpus, 100 * num_gpus, 500 * num_gpus] {
        group.throughput(Throughput::Elements(num_elems));
        let bench_id = format!("{bench_name}::{fn_name}::{type_name}::{num_elems}_elems");
        group.bench_with_input(&bench_id, &num_elems, |b, &num_elems| {
            let from_amounts = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let to_amounts = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let amounts = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();

            b.iter(|| {
                from_amounts
                    .par_iter()
                    .zip(to_amounts.par_iter().zip(amounts.par_iter()))
                    .for_each(|(from_amount, (to_amount, amount))| {
                        let (_, _) = transfer_func(from_amount, to_amount, amount);
                    })
            })
        });

        let params = client_key.computation_parameters();

        write_to_json::<u64, _>(
            &bench_id,
            params,
            params.name(),
            "erc20-transfer",
            &OperatorType::Atomic,
            64,
            vec![],
        );
    }
}

#[cfg(feature = "pbs-stats")]
use pbs_stats::print_transfer_pbs_counts;
#[cfg(feature = "gpu")]
use tfhe_cuda_backend::cuda_bind::cuda_get_number_of_gpus;

fn main() {
    #[cfg(not(feature = "gpu"))]
    let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
    #[cfg(feature = "gpu")]
    let params = PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS;

    let config = ConfigBuilder::with_custom_parameters(params).build();
    let cks = ClientKey::generate(config);
    let compressed_sks = CompressedServerKey::new(&cks);

    #[cfg(not(feature = "gpu"))]
    let sks = compressed_sks.decompress();
    #[cfg(feature = "gpu")]
    let sks = compressed_sks.decompress_to_gpu();

    rayon::broadcast(|_| set_server_key(sks.clone()));
    set_server_key(sks);

    let mut c = Criterion::default().sample_size(10).configure_from_args();

    // FheUint64 PBS counts
    // We don't run multiple times since every input is encrypted
    // PBS count is always the same
    #[cfg(feature = "pbs-stats")]
    {
        print_transfer_pbs_counts(
            &cks,
            "FheUint64",
            "whitepaper",
            transfer_whitepaper::<FheUint64>,
        );
        print_transfer_pbs_counts(&cks, "FheUint64", "no_cmux", transfer_no_cmux::<FheUint64>);
        print_transfer_pbs_counts(
            &cks,
            "FheUint64",
            "overflow",
            transfer_overflow::<FheUint64>,
        );
        print_transfer_pbs_counts(&cks, "FheUint64", "safe", transfer_safe::<FheUint64>);
    }

    // FheUint64 latency
    {
        let bench_name = if cfg!(feature = "gpu") {
            "hlapi::cuda::erc20::transfer_latency"
        } else {
            "hlapi::erc20::transfer_latency"
        };

        let mut group = c.benchmark_group(bench_name);
        bench_transfer_latency(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "whitepaper",
            transfer_whitepaper::<FheUint64>,
        );
        bench_transfer_latency(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "no_cmux",
            transfer_no_cmux::<FheUint64>,
        );
        bench_transfer_latency(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "overflow",
            transfer_overflow::<FheUint64>,
        );
        bench_transfer_latency(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "safe",
            transfer_safe::<FheUint64>,
        );

        group.finish();
    }

    // FheUint64 Throughput
    {
        let bench_name = if cfg!(feature = "gpu") {
            "hlapi::cuda::erc20::transfer_throughput"
        } else {
            "hlapi::erc20::transfer_throughput"
        };

        let mut group = c.benchmark_group(bench_name);
        bench_transfer_throughput(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "whitepaper",
            transfer_whitepaper::<FheUint64>,
        );
        bench_transfer_throughput(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "no_cmux",
            transfer_no_cmux::<FheUint64>,
        );
        bench_transfer_throughput(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "overflow",
            transfer_overflow::<FheUint64>,
        );
        bench_transfer_throughput(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "safe",
            transfer_safe::<FheUint64>,
        );
        group.finish();
    }

    c.final_summary();
}

#[path = "../utilities.rs"]
mod utilities;

#[cfg(feature = "gpu")]
use crate::utilities::configure_gpu;
use crate::utilities::{write_to_json, OperatorType};

use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion, Throughput};
use rand::prelude::*;
use rand::thread_rng;
use rayon::prelude::*;
use std::ops::{Add, Div, Mul, Sub};
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
use tfhe::shortint::parameters::*;
#[cfg(feature = "gpu")]
use tfhe::GpuIndex;
use tfhe::{
    set_server_key, ClientKey, CompressedServerKey, ConfigBuilder, FheBool, FheUint128, FheUint64,
};

pub(crate) fn transfer_whitepaper<FheType>(
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

#[allow(clippy::too_many_arguments)]
fn swap_request<FheType>(
    from_balance_0: &FheType,
    from_balance_1: &FheType,
    current_dex_balance_0: &FheType,
    current_dex_balance_1: &FheType,
    to_balance_0: &FheType,
    to_balance_1: &FheType,
    total_dex_token_0_in: &FheType,
    total_dex_token_1_in: &FheType,
    amount0: &FheType,
    amount1: &FheType,
) -> (FheType, FheType, FheType, FheType)
where
    FheType: Add<Output = FheType> + for<'a> FheOrd<&'a FheType> + Clone,
    FheBool: IfThenElse<FheType>,
    for<'a> &'a FheType: Add<Output = FheType> + Sub<Output = FheType>,
{
    let (_, new_current_balance_0) =
        transfer_whitepaper(from_balance_0, current_dex_balance_0, amount0);
    let (_, new_current_balance_1) =
        transfer_whitepaper(from_balance_1, current_dex_balance_1, amount1);
    let sent0 = &new_current_balance_0 - current_dex_balance_0;
    let sent1 = &new_current_balance_1 - current_dex_balance_1;
    let pending_0_in = to_balance_0 + &sent0;
    let pending_total_token_0_in = total_dex_token_0_in + &sent0;
    let pending_1_in = to_balance_1 + &sent1;
    let pending_total_token_1_in = total_dex_token_1_in + &sent1;
    (
        pending_0_in,
        pending_total_token_0_in,
        pending_1_in,
        pending_total_token_1_in,
    )
}

#[allow(clippy::too_many_arguments)]
fn swap_claim<FheType, BigFheType>(
    pending_0_in: &FheType,
    pending_1_in: &FheType,
    total_dex_token_0_in: u64,
    total_dex_token_1_in: u64,
    total_dex_token_0_out: u64,
    total_dex_token_1_out: u64,
    old_balance_0: &FheType,
    old_balance_1: &FheType,
    current_dex_balance_0: &FheType,
    current_dex_balance_1: &FheType,
) -> (FheType, FheType)
where
    FheType: CastFrom<FheBool>
        + for<'a> FheOrd<&'a FheType>
        + CastFrom<BigFheType>
        + Clone
        + Add<Output = FheType>,
    BigFheType: CastFrom<FheType> + Mul<u128, Output = BigFheType> + Div<u128, Output = BigFheType>,
    FheBool: IfThenElse<FheType>,
    for<'a> &'a FheType: Add<Output = FheType> + Sub<Output = FheType>,
{
    let mut new_balance_0 = old_balance_0.clone();
    let mut new_balance_1 = old_balance_1.clone();
    if total_dex_token_1_in != 0 {
        let big_pending_1_in = BigFheType::cast_from(pending_1_in.clone());
        let big_amount_0_out =
            (big_pending_1_in * total_dex_token_0_out as u128) / total_dex_token_1_in as u128;
        let amount_0_out = FheType::cast_from(big_amount_0_out);
        let (_, new_balance_0_tmp) =
            transfer_whitepaper(current_dex_balance_0, old_balance_0, &amount_0_out);
        new_balance_0 = new_balance_0_tmp;
    }
    if total_dex_token_0_in != 0 {
        let big_pending_0_in = BigFheType::cast_from(pending_0_in.clone());
        let big_amount_1_out =
            (big_pending_0_in * total_dex_token_1_out as u128) / total_dex_token_0_in as u128;
        let amount_1_out = FheType::cast_from(big_amount_1_out);
        let (_, new_balance_1_tmp) =
            transfer_whitepaper(current_dex_balance_1, old_balance_1, &amount_1_out);
        new_balance_1 = new_balance_1_tmp;
    }

    (new_balance_0, new_balance_1)
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

    pub fn print_swap_request_pbs_counts<FheType, F>(
        client_key: &ClientKey,
        type_name: &str,
        swap_request_func: F,
    ) where
        FheType: FheEncrypt<u64, ClientKey>,
        F: for<'a> Fn(
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
        ) -> (FheType, FheType, FheType, FheType),
    {
        let mut rng = thread_rng();

        let from_balance_0 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let from_balance_1 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let current_dex_balance_0 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let current_dex_balance_1 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let to_balance_0 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let to_balance_1 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let total_dex_token_0 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let total_dex_token_1 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let amount_0 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let amount_1 = FheType::encrypt(rng.gen::<u64>(), client_key);

        #[cfg(feature = "gpu")]
        configure_gpu(client_key);

        tfhe::reset_pbs_count();
        let (_, _, _, _) = swap_request_func(
            &from_balance_0,
            &from_balance_1,
            &current_dex_balance_0,
            &current_dex_balance_1,
            &to_balance_0,
            &to_balance_1,
            &total_dex_token_0,
            &total_dex_token_1,
            &amount_0,
            &amount_1,
        );
        let count = tfhe::get_pbs_count();

        println!("ERC20 swap request/::{type_name}: {count} PBS");

        let params = client_key.computation_parameters();

        let test_name = if cfg!(feature = "gpu") {
            format!("hlapi::cuda::dex::swap_request::pbs_count::{type_name}")
        } else {
            format!("hlapi::dex::swap_request::pbs_count::{type_name}")
        };

        let results_file = Path::new("dex_swap_request_pbs_count.csv");
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
    pub fn print_swap_claim_pbs_counts<FheType, F>(
        client_key: &ClientKey,
        type_name: &str,
        swap_claim_func: F,
    ) where
        FheType: FheEncrypt<u64, ClientKey>,
        F: for<'a> Fn(
            &'a FheType,
            &'a FheType,
            u64,
            u64,
            u64,
            u64,
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
        ) -> (FheType, FheType),
    {
        let mut rng = thread_rng();

        let pending_0_in = FheType::encrypt(rng.gen::<u64>(), client_key);
        let pending_1_in = FheType::encrypt(rng.gen::<u64>(), client_key);
        let total_dex_token_0_in = rng.gen::<u64>();
        let total_dex_token_1_in = rng.gen::<u64>();
        let total_dex_token_0_out = rng.gen::<u64>();
        let total_dex_token_1_out = rng.gen::<u64>();
        let old_balance_0 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let old_balance_1 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let current_dex_balance_0 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let current_dex_balance_1 = FheType::encrypt(rng.gen::<u64>(), client_key);

        #[cfg(feature = "gpu")]
        configure_gpu(client_key);

        tfhe::reset_pbs_count();
        let (_, _) = swap_claim_func(
            &pending_0_in,
            &pending_1_in,
            total_dex_token_0_in,
            total_dex_token_1_in,
            total_dex_token_0_out,
            total_dex_token_1_out,
            &old_balance_0,
            &old_balance_1,
            &current_dex_balance_0,
            &current_dex_balance_1,
        );
        let count = tfhe::get_pbs_count();

        println!("ERC20 swap claim/::{type_name}: {count} PBS");

        let params = client_key.computation_parameters();

        let test_name = if cfg!(feature = "gpu") {
            format!("hlapi::cuda::dex::swap_claim::pbs_count::{type_name}")
        } else {
            format!("hlapi::dex::swap_claim::pbs_count::{type_name}")
        };

        let results_file = Path::new("dex_swap_claim_pbs_count.csv");
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

fn bench_swap_request_latency<FheType, F>(
    c: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    bench_name: &str,
    type_name: &str,
    fn_name: &str,
    swap_request_func: F,
) where
    FheType: FheEncrypt<u64, ClientKey>,
    F: for<'a> Fn(
        &'a FheType,
        &'a FheType,
        &'a FheType,
        &'a FheType,
        &'a FheType,
        &'a FheType,
        &'a FheType,
        &'a FheType,
        &'a FheType,
        &'a FheType,
    ) -> (FheType, FheType, FheType, FheType),
{
    #[cfg(feature = "gpu")]
    configure_gpu(client_key);

    let bench_id = format!("{bench_name}::{fn_name}::{type_name}");
    c.bench_function(&bench_id, |b| {
        let mut rng = thread_rng();

        let from_balance_0 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let from_balance_1 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let current_balance_0 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let current_balance_1 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let to_balance_0 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let to_balance_1 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let total_token_0 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let total_token_1 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let amount_0 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let amount_1 = FheType::encrypt(rng.gen::<u64>(), client_key);

        b.iter(|| {
            let (_, _, _, _) = swap_request_func(
                &from_balance_0,
                &from_balance_1,
                &current_balance_0,
                &current_balance_1,
                &to_balance_0,
                &to_balance_1,
                &total_token_0,
                &total_token_1,
                &amount_0,
                &amount_1,
            );
        })
    });

    let params = client_key.computation_parameters();

    write_to_json::<u64, _>(
        &bench_id,
        params,
        params.name(),
        "dex-swap-request",
        &OperatorType::Atomic,
        64,
        vec![],
    );
}

fn bench_swap_claim_latency<FheType, F>(
    c: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    bench_name: &str,
    type_name: &str,
    fn_name: &str,
    swap_claim_func: F,
) where
    FheType: FheEncrypt<u64, ClientKey>,
    F: for<'a> Fn(
        &'a FheType,
        &'a FheType,
        u64,
        u64,
        u64,
        u64,
        &'a FheType,
        &'a FheType,
        &'a FheType,
        &'a FheType,
    ) -> (FheType, FheType),
{
    #[cfg(feature = "gpu")]
    configure_gpu(client_key);

    let bench_id = format!("{bench_name}::{fn_name}::{type_name}");
    c.bench_function(&bench_id, |b| {
        let mut rng = thread_rng();

        let pending_0_in = FheType::encrypt(rng.gen::<u64>(), client_key);
        let pending_1_in = FheType::encrypt(rng.gen::<u64>(), client_key);
        let total_token_0_in = rng.gen::<u64>();
        let total_token_1_in = rng.gen::<u64>();
        let total_token_0_out = rng.gen::<u64>();
        let total_token_1_out = rng.gen::<u64>();
        let old_balance_0 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let old_balance_1 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let current_balance_0 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let current_balance_1 = FheType::encrypt(rng.gen::<u64>(), client_key);

        b.iter(|| {
            let (_, _) = swap_claim_func(
                &pending_0_in,
                &pending_1_in,
                total_token_0_in,
                total_token_1_in,
                total_token_0_out,
                total_token_1_out,
                &old_balance_0,
                &old_balance_1,
                &current_balance_0,
                &current_balance_1,
            );
        })
    });

    let params = client_key.computation_parameters();

    write_to_json::<u64, _>(
        &bench_id,
        params,
        params.name(),
        "dex-swap-claim",
        &OperatorType::Atomic,
        64,
        vec![],
    );
}

#[cfg(not(feature = "gpu"))]
fn bench_swap_request_throughput<FheType, F>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    bench_name: &str,
    type_name: &str,
    fn_name: &str,
    swap_request_func: F,
) where
    FheType: FheEncrypt<u64, ClientKey> + Send + Sync,
    F: for<'a> Fn(
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
        ) -> (FheType, FheType, FheType, FheType)
        + Sync,
{
    let mut rng = thread_rng();

    for num_elems in [10, 100, 500] {
        group.throughput(Throughput::Elements(num_elems));
        let bench_id =
            format!("{bench_name}::throughput::{fn_name}::{type_name}::{num_elems}_elems");
        group.bench_with_input(&bench_id, &num_elems, |b, &num_elems| {
            let from_balances_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let from_balances_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let current_dex_balances_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let current_dex_balances_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let to_balances_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let to_balances_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let total_dex_tokens_0_in = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let total_dex_tokens_1_in = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let amounts_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let amounts_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();

            b.iter(|| {
                from_balances_0
                    .par_iter()
                    .zip(from_balances_1.par_iter().zip(
                        current_dex_balances_0.par_iter().zip(
                            current_dex_balances_1.par_iter().zip(
                                to_balances_0.par_iter().zip(
                                    to_balances_1.par_iter().zip(
                                        total_dex_tokens_0_in.par_iter().zip(
                                            total_dex_tokens_1_in.par_iter().zip(
                                                amounts_0.par_iter().zip(amounts_1.par_iter()),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ))
                    .for_each(
                        |(
                            from_balance_0,
                            (
                                from_balance_1,
                                (
                                    current_balance_0,
                                    (
                                        current_balance_1,
                                        (
                                            to_balance_0,
                                            (
                                                to_balance_1,
                                                (
                                                    total_token_0_in,
                                                    (total_token_1_in, (amount_0, amount_1)),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        )| {
                            let (_, _, _, _) = swap_request_func(
                                from_balance_0,
                                from_balance_1,
                                current_balance_0,
                                current_balance_1,
                                to_balance_0,
                                to_balance_1,
                                total_token_0_in,
                                total_token_1_in,
                                amount_0,
                                amount_1,
                            );
                        },
                    )
            })
        });

        let params = client_key.computation_parameters();

        write_to_json::<u64, _>(
            &bench_id,
            params,
            params.name(),
            "dex-swap",
            &OperatorType::Atomic,
            64,
            vec![],
        );
    }
}
#[cfg(feature = "gpu")]
fn cuda_bench_swap_request_throughput<FheType, F>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    bench_name: &str,
    type_name: &str,
    fn_name: &str,
    swap_request_func: F,
) where
    FheType: FheEncrypt<u64, ClientKey> + Send + Sync,
    F: for<'a> Fn(
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
            &'a FheType,
        ) -> (FheType, FheType, FheType, FheType)
        + Sync,
{
    let mut rng = thread_rng();
    let num_gpus = get_number_of_gpus() as u64;
    let compressed_server_key = CompressedServerKey::new(client_key);

    let sks_vec = (0..num_gpus)
        .map(|i| compressed_server_key.decompress_to_specific_gpu(GpuIndex::new(i as u32)))
        .collect::<Vec<_>>();

    for num_elems in [10 * num_gpus, 100 * num_gpus, 500 * num_gpus] {
        group.throughput(Throughput::Elements(num_elems));
        let bench_id =
            format!("{bench_name}::throughput::{fn_name}::{type_name}::{num_elems}_elems");
        group.bench_with_input(&bench_id, &num_elems, |b, &num_elems| {
            let from_balances_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let from_balances_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let current_dex_balances_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let current_dex_balances_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let to_balances_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let to_balances_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let total_dex_tokens_0_in = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let total_dex_tokens_1_in = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let amounts_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let amounts_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();


            let num_streams_per_gpu = 8; // Hard coded stream value for FheUint64
            let chunk_size = (num_elems / num_gpus) as usize;

            b.iter(|| {
                from_balances_0
                    .par_chunks(chunk_size) // Split into chunks of num_gpus
                    .zip(from_balances_1.par_chunks(chunk_size)
                            .zip(current_dex_balances_0.par_chunks(chunk_size)
                                    .zip(current_dex_balances_1.par_chunks(chunk_size)
                                            .zip(to_balances_0.par_chunks(chunk_size)
                                                    .zip(to_balances_1.par_chunks(chunk_size)
                                                            .zip(total_dex_tokens_0_in.par_chunks(chunk_size)
                                                                    .zip(total_dex_tokens_1_in.par_chunks(chunk_size)
                                                                            .zip(amounts_0.par_chunks(chunk_size)
                                                                                    .zip(amounts_1.par_chunks(chunk_size)
                            ))))))))) // Zip with the other data
                    .enumerate() // Get the index for GPU
                    .for_each(
                        |(i, (from_balances_0_gpu_i, (from_balances_1_gpu_i, (current_dex_balances_0_gpu_i, (current_dex_balances_1_gpu_i, (to_balances_0_gpu_i, (to_balances_1_gpu_i, (total_dex_tokens_0_in_gpu_i, (total_dex_tokens_1_in_gpu_i, (amounts_0_gpu_i, amounts_1_gpu_i))))))))))| {
                            // Process chunks within each GPU
                            let stream_chunk_size = from_balances_0_gpu_i.len() / num_streams_per_gpu;
                            from_balances_0_gpu_i.par_chunks(stream_chunk_size)
                                .zip(from_balances_1_gpu_i.par_chunks(stream_chunk_size)
                                        .zip(current_dex_balances_0_gpu_i.par_chunks(stream_chunk_size)
                                            .zip(current_dex_balances_1_gpu_i.par_chunks(stream_chunk_size)
                                                     .zip(to_balances_0_gpu_i.par_chunks(stream_chunk_size)
                                                         .zip(to_balances_1_gpu_i.par_chunks(stream_chunk_size)
                                                                  .zip(total_dex_tokens_0_in_gpu_i.par_chunks(stream_chunk_size)
                                                                      .zip(total_dex_tokens_1_in_gpu_i.par_chunks(stream_chunk_size)
                                                                               .zip(amounts_0_gpu_i.par_chunks(stream_chunk_size)
                                                                                   .zip(amounts_1_gpu_i.par_chunks(stream_chunk_size)
                                )))))))))
                                .for_each(
                                    |(from_balances_0_on_stream,
                                      (from_balances_1_on_stream,
                                       (current_dex_balances_0_on_stream,
                                        (current_dex_balances_1_on_stream,
                                         (to_balances_0_on_stream,
                                          (to_balances_1_on_stream,
                                           (total_dex_tokens_0_in_on_stream,
                                            (total_dex_tokens_1_in_on_stream,
                                             (amounts_0_on_stream,
                                              amounts_1_on_stream
                                              )))))))))| {
                                        // Set the server key for the current GPU
                                        set_server_key(sks_vec[i].clone());
                                        // Parallel iteration over the chunks of data
                                        from_balances_0_on_stream.iter()
                                            .zip(from_balances_1_on_stream.iter()
                                                .zip(current_dex_balances_0_on_stream.iter()
                                                    .zip(current_dex_balances_1_on_stream.iter()
                                                        .zip(to_balances_0_on_stream.iter()
                                                            .zip(to_balances_1_on_stream.iter()
                                                                .zip(total_dex_tokens_0_in_on_stream.iter()
                                                                    .zip(total_dex_tokens_1_in_on_stream.iter()
                                                                        .zip(amounts_0_on_stream.iter()
                                                                            .zip(amounts_1_on_stream.iter()
                                                )))))))))
                                            .for_each(|(from_balance_0,
                                                           (from_balance_1,
                                                            (current_dex_balance_0,
                                                             (current_dex_balance_1,
                                                              (to_balance_0,
                                                               (to_balance_1,
                                                                (total_dex_token_0,
                                                                 (total_dex_token_1,
                                                                  (amount_0,
                                                                   amount_1,
                                                                   )))))))))| {
                                                swap_request_func(
                                                    from_balance_0,
                                                    from_balance_1,
                                                    current_dex_balance_0,
                                                    current_dex_balance_1,
                                                    to_balance_0,
                                                    to_balance_1,
                                                    total_dex_token_0,
                                                    total_dex_token_1,
                                                    amount_0,
                                                    amount_1,
                                                );
                                            });
                                    },
                                );
                        },
                    );
            });
        });

        let params = client_key.computation_parameters();

        write_to_json::<u64, _>(
            &bench_id,
            params,
            params.name(),
            "dex-swap",
            &OperatorType::Atomic,
            64,
            vec![],
        );
    }
}

#[cfg(feature = "pbs-stats")]
use crate::pbs_stats::print_swap_claim_pbs_counts;
#[cfg(feature = "pbs-stats")]
use crate::pbs_stats::print_swap_request_pbs_counts;
#[cfg(feature = "gpu")]
use tfhe::core_crypto::gpu::get_number_of_gpus;

#[cfg(not(feature = "gpu"))]
fn main() {
    let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let config = ConfigBuilder::with_custom_parameters(params).build();
    let cks = ClientKey::generate(config);
    let compressed_sks = CompressedServerKey::new(&cks);

    let sks = compressed_sks.decompress();

    rayon::broadcast(|_| set_server_key(sks.clone()));
    set_server_key(sks);

    let mut c = Criterion::default().sample_size(10).configure_from_args();

    let bench_name = "hlapi::dex";

    // FheUint64 PBS counts
    // We don't run multiple times since every input is encrypted
    // PBS count is always the same
    #[cfg(feature = "pbs-stats")]
    {
        print_swap_request_pbs_counts(&cks, "FheUint64", swap_request::<FheUint64>);
        print_swap_claim_pbs_counts(&cks, "FheUint64", swap_claim::<FheUint64, FheUint128>);
    }

    // FheUint64 latency
    {
        let mut group = c.benchmark_group(bench_name);
        bench_swap_request_latency(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "swap_request",
            swap_request::<FheUint64>,
        );
        bench_swap_claim_latency(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "swap_claim",
            swap_claim::<FheUint64, FheUint128>,
        );

        group.finish();
    }

    // FheUint64 Throughput
    {
        let mut group = c.benchmark_group(bench_name);
        bench_swap_request_throughput(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "swap_request",
            swap_request::<FheUint64>,
        );

        group.finish();
    }

    c.final_summary();
}

#[cfg(feature = "gpu")]
fn main() {
    let params = PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS;

    let config = ConfigBuilder::with_custom_parameters(params).build();
    let cks = ClientKey::generate(config);

    let mut c = Criterion::default().sample_size(10).configure_from_args();

    let bench_name = "hlapi::cuda::dex";

    // FheUint64 PBS counts
    // We don't run multiple times since every input is encrypted
    // PBS count is always the same
    #[cfg(feature = "pbs-stats")]
    {
        print_swap_request_pbs_counts(&cks, "FheUint64", swap_request::<FheUint64>);
        print_swap_claim_pbs_counts(&cks, "FheUint64", swap_claim::<FheUint64, FheUint128>);
    }

    // FheUint64 latency
    {
        let mut group = c.benchmark_group(bench_name);
        bench_swap_request_latency(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "swap_request",
            swap_request::<FheUint64>,
        );
        bench_swap_claim_latency(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "swap_claim",
            swap_claim::<FheUint64, FheUint128>,
        );

        group.finish();
    }

    // FheUint64 Throughput
    {
        let mut group = c.benchmark_group(bench_name);
        cuda_bench_swap_request_throughput(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "swap_request",
            swap_request::<FheUint64>,
        );
        group.finish();
    }

    c.final_summary();
}

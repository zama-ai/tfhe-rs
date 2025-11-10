#[cfg(feature = "gpu")]
use benchmark::params_aliases::BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
#[cfg(not(feature = "gpu"))]
use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
#[cfg(feature = "gpu")]
use benchmark::utilities::configure_gpu;
use benchmark::utilities::{get_bench_type, write_to_json, BenchmarkType, OperatorType};
use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion, Throughput};
use rand::prelude::*;
use rand::thread_rng;
use rayon::prelude::*;
use std::ops::{Add, Div, Mul, Sub};
#[cfg(feature = "gpu")]
use tfhe::core_crypto::gpu::get_number_of_gpus;
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
#[cfg(not(feature = "gpu"))]
use tfhe::{set_server_key, CompressedServerKey};
#[cfg(feature = "gpu")]
use tfhe::{set_server_key, CompressedServerKey, GpuIndex};
use tfhe::{ClientKey, ConfigBuilder, FheBool, FheUint128, FheUint64};

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

#[allow(clippy::too_many_arguments)]
fn swap_request_update_dex_balance_whitepaper<FheType>(
    from_balance: &FheType,
    current_dex_balance: &FheType,
    amount: &FheType,
) -> FheType
where
    FheType: Add<Output = FheType> + for<'a> FheOrd<&'a FheType> + Clone + Send + Sync,
    FheBool: IfThenElse<FheType>,
    for<'a> &'a FheType: Add<Output = FheType> + Sub<Output = FheType>,
{
    let (_, new_current_balance) = transfer_whitepaper(from_balance, current_dex_balance, amount);
    &new_current_balance - current_dex_balance
}

#[allow(clippy::too_many_arguments)]
fn swap_request_update_dex_balance_no_cmux<FheType>(
    from_balance: &FheType,
    current_dex_balance: &FheType,
    amount: &FheType,
) -> FheType
where
    FheType: Add<Output = FheType>
        + for<'a> FheOrd<&'a FheType>
        + CastFrom<FheBool>
        + Clone
        + Send
        + Sync,
    FheBool: IfThenElse<FheType>,
    for<'a> &'a FheType:
        Add<Output = FheType> + Sub<Output = FheType> + Mul<FheType, Output = FheType>,
{
    let (_, new_current_balance) = transfer_no_cmux(from_balance, current_dex_balance, amount);
    &new_current_balance - current_dex_balance
}

#[allow(clippy::too_many_arguments)]
fn swap_request_finalize<FheType>(
    to_balance: &FheType,
    total_dex_token_in: &FheType,
    sent: &FheType,
) -> (FheType, FheType)
where
    FheType: Add<Output = FheType> + for<'a> FheOrd<&'a FheType> + Clone + Send + Sync,
    FheBool: IfThenElse<FheType>,
    for<'a> &'a FheType: Add<Output = FheType> + Sub<Output = FheType>,
{
    let pending_0_in = to_balance + sent;
    let pending_total_token_0_in = total_dex_token_in + sent;
    (pending_0_in, pending_total_token_0_in)
}

#[allow(clippy::too_many_arguments)]
fn swap_claim_prepare<FheType, BigFheType>(
    pending_0_in: &FheType,
    pending_1_in: &FheType,
    total_dex_token_0_in: u64,
    total_dex_token_1_in: u64,
    total_dex_token_0_out: u64,
    total_dex_token_1_out: u64,
) -> (FheType, FheType)
where
    FheType: CastFrom<FheBool>
        + for<'a> FheOrd<&'a FheType>
        + CastFrom<BigFheType>
        + Clone
        + Add<Output = FheType>
        + Send
        + Sync,
    BigFheType: CastFrom<FheType> + Mul<u128, Output = BigFheType> + Div<u128, Output = BigFheType>,
    FheBool: IfThenElse<FheType>,
    for<'a> &'a FheType: Add<Output = FheType> + Sub<Output = FheType>,
{
    let (amount_0_out, amount_1_out) = rayon::join(
        || {
            let mut amount_0_out = pending_1_in.clone();
            if total_dex_token_1_in != 0 {
                let big_pending_1_in = BigFheType::cast_from(pending_1_in.clone());
                let big_amount_0_out = (big_pending_1_in * total_dex_token_0_out as u128)
                    / total_dex_token_1_in as u128;
                amount_0_out = FheType::cast_from(big_amount_0_out);
            }
            amount_0_out
        },
        || {
            let mut amount_1_out = pending_0_in.clone();
            if total_dex_token_0_in != 0 {
                let big_pending_0_in = BigFheType::cast_from(pending_0_in.clone());
                let big_amount_1_out = (big_pending_0_in * total_dex_token_1_out as u128)
                    / total_dex_token_0_in as u128;
                amount_1_out = FheType::cast_from(big_amount_1_out);
            }
            amount_1_out
        },
    );

    (amount_0_out, amount_1_out)
}

#[allow(clippy::too_many_arguments)]
fn swap_claim_update_dex_balance_whitepaper<FheType>(
    amount_out: &FheType,
    total_dex_other_token_in: u64,
    old_balance: &FheType,
    current_dex_balance: &FheType,
) -> FheType
where
    FheType: CastFrom<FheBool>
        + for<'a> FheOrd<&'a FheType>
        + Clone
        + Add<Output = FheType>
        + Send
        + Sync,
    FheBool: IfThenElse<FheType>,
    for<'a> &'a FheType: Add<Output = FheType> + Sub<Output = FheType>,
{
    let mut new_balance = old_balance.clone();
    if total_dex_other_token_in != 0 {
        let (_, new_balance_tmp) =
            transfer_whitepaper(current_dex_balance, old_balance, amount_out);
        new_balance = new_balance_tmp;
    }
    new_balance
}

#[allow(clippy::too_many_arguments)]
fn swap_claim_update_dex_balance_no_cmux<FheType>(
    amount_out: &FheType,
    total_dex_other_token_in: u64,
    old_balance: &FheType,
    current_dex_balance: &FheType,
) -> FheType
where
    FheType: CastFrom<FheBool>
        + for<'a> FheOrd<&'a FheType>
        + Clone
        + Add<Output = FheType>
        + Send
        + Sync,
    FheBool: IfThenElse<FheType>,
    for<'a> &'a FheType:
        Add<Output = FheType> + Sub<Output = FheType> + Mul<FheType, Output = FheType>,
{
    let mut new_balance = old_balance.clone();
    if total_dex_other_token_in != 0 {
        let (_, new_balance_tmp) = transfer_no_cmux(current_dex_balance, old_balance, amount_out);
        new_balance = new_balance_tmp;
    }
    new_balance
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

    pub fn print_swap_request_update_dex_balance_pbs_counts<FheType, F>(
        client_key: &ClientKey,
        type_name: &str,
        fn_name: &str,
        swap_request_update_dex_balance_func: F,
    ) where
        FheType: FheEncrypt<u64, ClientKey>,
        F: for<'a> Fn(&'a FheType, &'a FheType, &'a FheType) -> FheType,
    {
        let mut rng = thread_rng();

        let from_balance = FheType::encrypt(rng.gen::<u64>(), client_key);
        let current_dex_balance = FheType::encrypt(rng.gen::<u64>(), client_key);
        let amount = FheType::encrypt(rng.gen::<u64>(), client_key);

        #[cfg(feature = "gpu")]
        configure_gpu(client_key);

        tfhe::reset_pbs_count();
        let _ = swap_request_update_dex_balance_func(&from_balance, &current_dex_balance, &amount);
        let count = tfhe::get_pbs_count() * 2;

        println!("ERC20 swap request update dex balance/::{type_name}: {count} PBS");

        let params = client_key.computation_parameters();
        let params_name = params.name();

        let test_name = if cfg!(feature = "gpu") {
            format!("hlapi::cuda::dex::pbs_count::swap_request_update_dex_balance::{fn_name}::{params_name}::{type_name}")
        } else {
            format!(
                "hlapi::dex::pbs_count::swap_request_update_dex_balance::{fn_name}::{params_name}::{type_name}"
            )
        };

        let results_file = Path::new("dex_swap_request_update_dex_balance_pbs_count.csv");
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
            params_name,
            "pbs-count",
            &OperatorType::Atomic,
            0,
            vec![],
        );
    }
    pub fn print_swap_request_finalize_pbs_counts<FheType, F>(
        client_key: &ClientKey,
        type_name: &str,
        swap_request_finalize_func: F,
    ) where
        FheType: FheEncrypt<u64, ClientKey>,
        F: for<'a> Fn(&'a FheType, &'a FheType, &'a FheType) -> (FheType, FheType),
    {
        let mut rng = thread_rng();

        let to_balance_0 = FheType::encrypt(rng.gen::<u64>(), client_key);
        let total_dex_token_0_in = FheType::encrypt(rng.gen::<u64>(), client_key);
        let sent_0 = FheType::encrypt(rng.gen::<u64>(), client_key);

        #[cfg(feature = "gpu")]
        configure_gpu(client_key);

        tfhe::reset_pbs_count();
        let (_, _) = swap_request_finalize_func(&to_balance_0, &total_dex_token_0_in, &sent_0);
        let count = tfhe::get_pbs_count() * 2;

        println!("ERC20 swap request finalize/::{type_name}: {count} PBS");

        let params = client_key.computation_parameters();
        let params_name = params.name();

        let test_name = if cfg!(feature = "gpu") {
            format!(
                "hlapi::cuda::dex::pbs_count::swap_request_finalize::{params_name}::{type_name}"
            )
        } else {
            format!("hlapi::dex::pbs_count::swap_request_finalize::{params_name}::{type_name}")
        };

        let results_file = Path::new("dex_swap_request_finalize_pbs_count.csv");
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
            params_name,
            "pbs-count",
            &OperatorType::Atomic,
            0,
            vec![],
        );
    }
    pub fn print_swap_claim_prepare_pbs_counts<FheType, F>(
        client_key: &ClientKey,
        type_name: &str,
        swap_claim_prepare_func: F,
    ) where
        FheType: FheEncrypt<u64, ClientKey>,
        F: for<'a> Fn(&'a FheType, &'a FheType, u64, u64, u64, u64) -> (FheType, FheType),
    {
        let mut rng = thread_rng();

        let pending_0_in = FheType::encrypt(rng.gen::<u64>(), client_key);
        let pending_1_in = FheType::encrypt(rng.gen::<u64>(), client_key);
        let total_dex_token_0_in = rng.gen::<u64>();
        let total_dex_token_1_in = rng.gen::<u64>();
        let total_dex_token_0_out = rng.gen::<u64>();
        let total_dex_token_1_out = rng.gen::<u64>();

        #[cfg(feature = "gpu")]
        configure_gpu(client_key);

        tfhe::reset_pbs_count();
        let (_, _) = swap_claim_prepare_func(
            &pending_0_in,
            &pending_1_in,
            total_dex_token_0_in,
            total_dex_token_1_in,
            total_dex_token_0_out,
            total_dex_token_1_out,
        );
        let count = tfhe::get_pbs_count();

        println!("ERC20 swap claim prepare/::{type_name}: {count} PBS");

        let params = client_key.computation_parameters();
        let params_name = params.name();

        let test_name = if cfg!(feature = "gpu") {
            format!("hlapi::cuda::pbs_count::dex::swap_claim_prepare::{params_name}::{type_name}")
        } else {
            format!("hlapi::dex::pbs_count::swap_claim_prepare::{params_name}::{type_name}")
        };

        let results_file = Path::new("dex_swap_claim_prepare_pbs_count.csv");
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
            params_name,
            "pbs-count",
            &OperatorType::Atomic,
            0,
            vec![],
        );
    }
    pub fn print_swap_claim_update_dex_balance_pbs_counts<FheType, F>(
        client_key: &ClientKey,
        type_name: &str,
        fn_name: &str,
        swap_claim_update_dex_balance_func: F,
    ) where
        FheType: FheEncrypt<u64, ClientKey>,
        F: for<'a> Fn(&'a FheType, u64, &'a FheType, &'a FheType) -> FheType,
    {
        let mut rng = thread_rng();

        let amount_out = FheType::encrypt(rng.gen::<u64>(), client_key);
        let total_dex_token_in = rng.gen::<u64>();
        let old_balance = FheType::encrypt(rng.gen::<u64>(), client_key);
        let current_dex_balance = FheType::encrypt(rng.gen::<u64>(), client_key);

        #[cfg(feature = "gpu")]
        configure_gpu(client_key);

        tfhe::reset_pbs_count();
        let _ = swap_claim_update_dex_balance_func(
            &amount_out,
            total_dex_token_in,
            &old_balance,
            &current_dex_balance,
        );
        let count = tfhe::get_pbs_count() * 2;

        println!("ERC20 swap claim update dex balance/::{type_name}: {count} PBS");

        let params = client_key.computation_parameters();
        let params_name = params.name();

        let test_name = if cfg!(feature = "gpu") {
            format!("hlapi::cuda::pbs_count::dex::swap_claim_update_dex_balance::{fn_name}::{params_name}::{type_name}")
        } else {
            format!("hlapi::dex::pbs_count::swap_claim_update_dex_balance::{fn_name}::{params_name}::{type_name}")
        };

        let results_file = Path::new("dex_swap_claim_update_dex_balance_pbs_count.csv");
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
            params_name,
            "pbs-count",
            &OperatorType::Atomic,
            0,
            vec![],
        );
    }
}

fn bench_swap_request_latency<FheType, F1, F2>(
    c: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    bench_name: &str,
    type_name: &str,
    fn_name: &str,
    swap_request_update_dex_balance_func: F1,
    swap_request_finalize_func: F2,
) where
    FheType: FheEncrypt<u64, ClientKey> + Send + Sync,
    F1: for<'a> Fn(&'a FheType, &'a FheType, &'a FheType) -> FheType + Sync,
    F2: for<'a> Fn(&'a FheType, &'a FheType, &'a FheType) -> (FheType, FheType) + Sync,
{
    #[cfg(feature = "gpu")]
    configure_gpu(client_key);

    let params = client_key.computation_parameters();
    let params_name = params.name();

    let bench_id = format!("{bench_name}::{fn_name}::{type_name}");
    println!("{bench_id}");
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
            let (sent0, sent1) = rayon::join(
                || {
                    swap_request_update_dex_balance_func(
                        &from_balance_0,
                        &current_balance_0,
                        &amount_0,
                    )
                },
                || {
                    swap_request_update_dex_balance_func(
                        &from_balance_1,
                        &current_balance_1,
                        &amount_1,
                    )
                },
            );
            let ((_, _), (_, _)) = rayon::join(
                || swap_request_finalize_func(&to_balance_0, &total_token_0, &sent0),
                || swap_request_finalize_func(&to_balance_1, &total_token_1, &sent1),
            );
        })
    });

    write_to_json::<u64, _>(
        &bench_id,
        params,
        params_name,
        "dex-swap-request",
        &OperatorType::Atomic,
        64,
        vec![],
    );
}

#[cfg(not(feature = "gpu"))]
fn bench_swap_request_throughput<FheType, F1, F2>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    bench_name: &str,
    type_name: &str,
    fn_name: &str,
    swap_request_update_dex_balance_func: F1,
    swap_request_finalize_func: F2,
) where
    FheType: FheEncrypt<u64, ClientKey> + Send + Sync,
    F1: for<'a> Fn(&'a FheType, &'a FheType, &'a FheType) -> FheType + Sync,
    F2: for<'a> Fn(&'a FheType, &'a FheType, &'a FheType) -> (FheType, FheType) + Sync,
{
    let mut rng = thread_rng();

    let params = client_key.computation_parameters();
    let params_name = params.name();

    for num_elems in [10, 50, 100] {
        group.throughput(Throughput::Elements(num_elems));
        let bench_id = format!(
            "{bench_name}::throughput::{fn_name}::{params_name}::{type_name}::{num_elems}_elems"
        );
        println!("{bench_id}");
        group.bench_with_input(&bench_id, &num_elems, |b, &num_elems| {
            let from_balances_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let from_balances_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let current_balances_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let current_balances_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let to_balances_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let to_balances_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let total_tokens_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let total_tokens_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let amount_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let amount_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();

            b.iter(|| {
                let (sents_0, sents_1): (Vec<_>, Vec<_>) = rayon::join(
                    || {
                        from_balances_0
                            .iter()
                            .zip(current_balances_0.iter())
                            .zip(amount_0.iter())
                            .map(|((from_0, curr_0), amt_0)| {
                                swap_request_update_dex_balance_func(from_0, curr_0, amt_0)
                            })
                            .collect()
                    },
                    || {
                        from_balances_1
                            .iter()
                            .zip(current_balances_1.iter())
                            .zip(amount_1.iter())
                            .map(|((from_1, curr_1), amt_1)| {
                                swap_request_update_dex_balance_func(from_1, curr_1, amt_1)
                            })
                            .collect()
                    },
                );

                rayon::join(
                    || {
                        to_balances_0
                            .par_iter()
                            .zip(total_tokens_0.par_iter())
                            .zip(sents_0.par_iter())
                            .for_each(|((to_balance_0, total_token_0), sent_0)| {
                                let (_, _) =
                                    swap_request_finalize_func(to_balance_0, total_token_0, sent_0);
                            })
                    },
                    || {
                        to_balances_1
                            .par_iter()
                            .zip(total_tokens_1.par_iter())
                            .zip(sents_1.par_iter())
                            .for_each(|((to_balance_1, total_token_1), sent_1)| {
                                let (_, _) =
                                    swap_request_finalize_func(to_balance_1, total_token_1, sent_1);
                            })
                    },
                );
            })
        });

        write_to_json::<u64, _>(
            &bench_id,
            params,
            &params_name,
            "dex-swap-request",
            &OperatorType::Atomic,
            64,
            vec![],
        );
    }
}
#[cfg(feature = "gpu")]
fn cuda_bench_swap_request_throughput<FheType, F1, F2>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    bench_name: &str,
    type_name: &str,
    fn_name: &str,
    swap_request_update_dex_balance_func: F1,
    swap_request_finalize_func: F2,
) where
    FheType: FheEncrypt<u64, ClientKey> + Send + Sync,
    F1: for<'a> Fn(&'a FheType, &'a FheType, &'a FheType) -> FheType + Sync,
    F2: for<'a> Fn(&'a FheType, &'a FheType, &'a FheType) -> (FheType, FheType) + Sync,
{
    let mut rng = thread_rng();
    let num_gpus = get_number_of_gpus() as u64;
    let compressed_server_key = CompressedServerKey::new(client_key);

    let sks_vec = (0..num_gpus)
        .map(|i| compressed_server_key.decompress_to_specific_gpu(GpuIndex::new(i as u32)))
        .collect::<Vec<_>>();
    let dex_balance_update_sks = compressed_server_key.decompress_to_gpu();

    let params = client_key.computation_parameters();
    let params_name = params.name();

    for num_elems in [5 * num_gpus, 10 * num_gpus, 20 * num_gpus] {
        group.throughput(Throughput::Elements(num_elems));
        let bench_id = format!(
            "{bench_name}::throughput::{fn_name}::{params_name}::{type_name}::{num_elems}_elems"
        );
        println!("{bench_id}");
        group.bench_with_input(&bench_id, &num_elems, |b, &num_elems| {
            let from_balances_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let from_balances_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let current_balances_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let current_balances_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let to_balances_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let to_balances_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let total_tokens_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let total_tokens_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let amount_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let amount_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();

            let num_streams_per_gpu = 4;
            let chunk_size = (num_elems / num_gpus) as usize;
            b.iter(|| {
                let (sents_0, sents_1): (Vec<_>, Vec<_>) = rayon::join(
                    || {
                        set_server_key(dex_balance_update_sks.clone());
                        from_balances_0
                            .iter()
                            .zip(current_balances_0.iter())
                            .zip(amount_0.iter())
                            .map(|((from_0, curr_0), amt_0)| {
                                swap_request_update_dex_balance_func(from_0, curr_0, amt_0)
                            })
                            .collect()
                    },
                    || {
                        set_server_key(dex_balance_update_sks.clone());
                        from_balances_1
                            .iter()
                            .zip(current_balances_1.iter())
                            .zip(amount_1.iter())
                            .map(|((from_1, curr_1), amt_1)| {
                                swap_request_update_dex_balance_func(from_1, curr_1, amt_1)
                            })
                            .collect()
                    },
                );

                rayon::join(||{
                    to_balances_0
                        .par_chunks(chunk_size)
                        .zip(total_tokens_1.par_chunks(chunk_size))
                        .zip(sents_0.par_chunks(chunk_size))
                        .enumerate()
                        .for_each(
                            |(
                                 i,
                                 (
                                                 (to_balances_0_gpu_i,
                                                 total_tokens_1_gpu_i,
                                             ),
                                         sents_0_gpu_i,
                                 ),
                             )| {
                                let stream_chunk_size = to_balances_0_gpu_i.len() / num_streams_per_gpu;
                                to_balances_0_gpu_i
                                    .par_chunks(stream_chunk_size)
                                    .zip(total_tokens_1_gpu_i.par_chunks(stream_chunk_size))
                                    .zip(sents_0_gpu_i.par_chunks(stream_chunk_size))
                                    .for_each(
                                        |(
                                                         (to_balances_0_chunk,
                                                     total_tokens_1_chunk,
                                                 ),
                                                 sents_0_chunk,
                                         )| {
                                            // Set the server key for the current GPU
                                            set_server_key(sks_vec[i].clone());
                                            to_balances_0_chunk
                                                .iter()
                                                .zip(total_tokens_1_chunk.iter())
                                                .zip(sents_0_chunk.iter())
                                                .for_each(
                                                    |(
                                                                     (to_balance_0,
                                                                 total_token_1,
                                                             ),
                                                             sent_0,
                                                     )| {
                                                        let (_, _) = swap_request_finalize_func(
                                                            to_balance_0,
                                                            total_token_1,
                                                            sent_0,
                                                        );
                                                    },
                                                );
                                        },
                                    );
                            },
                        );
                },
                            || {

                                to_balances_1
                                    .par_chunks(chunk_size)
                                    .zip(total_tokens_0.par_chunks(chunk_size))
                                    .zip(sents_1.par_chunks(chunk_size))
                                    .enumerate()
                                    .for_each(
                                        |(
                                             i,
                                             (
                                                 (to_balances_1_gpu_i,
                                                     total_tokens_0_gpu_i,
                                                 ),
                                                 sents_1_gpu_i,
                                             ),
                                         )| {
                                            let stream_chunk_size = to_balances_1_gpu_i.len() / num_streams_per_gpu;
                                            to_balances_1_gpu_i
                                                .par_chunks(stream_chunk_size)
                                                .zip(total_tokens_0_gpu_i.par_chunks(stream_chunk_size))
                                                .zip(sents_1_gpu_i.par_chunks(stream_chunk_size))
                                                .for_each(
                                                    |(
                                                         (to_balances_1_chunk,
                                                             total_tokens_0_chunk,
                                                         ),
                                                         sents_1_chunk,
                                                     )| {
                                                        // Set the server key for the current GPU
                                                        set_server_key(sks_vec[i].clone());
                                                        to_balances_1_chunk
                                                            .iter()
                                                            .zip(total_tokens_0_chunk.iter())
                                                            .zip(sents_1_chunk.iter())
                                                            .for_each(
                                                                |(
                                                                     (to_balance_1,
                                                                         total_token_0,
                                                                     ),
                                                                     sent_1,
                                                                 )| {
                                                                    let (_, _) = swap_request_finalize_func(
                                                                        to_balance_1,
                                                                        total_token_0,
                                                                        sent_1,
                                                                    );
                                                                },
                                                            );
                                                    },
                                                );
                                        },
                                    );
                            });
                                })
        });

        write_to_json::<u64, _>(
            &bench_id,
            params,
            &params_name,
            "dex-swap-request",
            &OperatorType::Atomic,
            64,
            vec![],
        );
    }
}

fn bench_swap_claim_latency<FheType, F1, F2>(
    c: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    bench_name: &str,
    type_name: &str,
    fn_name: &str,
    swap_claim_prepare_func: F1,
    swap_claim_update_dex_balance_func: F2,
) where
    FheType: FheEncrypt<u64, ClientKey> + Send + Sync,
    F1: for<'a> Fn(&'a FheType, &'a FheType, u64, u64, u64, u64) -> (FheType, FheType),
    F2: for<'a> Fn(&'a FheType, u64, &'a FheType, &'a FheType) -> FheType + Sync,
{
    #[cfg(feature = "gpu")]
    configure_gpu(client_key);

    let params = client_key.computation_parameters();
    let params_name = params.name();

    let bench_id = format!("{bench_name}::{fn_name}::{params_name}::{type_name}");
    println!("{bench_id}");
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
            let (amount_0_out, amount_1_out) = swap_claim_prepare_func(
                &pending_0_in,
                &pending_1_in,
                total_token_0_in,
                total_token_1_in,
                total_token_0_out,
                total_token_1_out,
            );
            let (_, _) = rayon::join(
                || {
                    swap_claim_update_dex_balance_func(
                        &amount_0_out,
                        total_token_1_in,
                        &old_balance_0,
                        &current_balance_0,
                    )
                },
                || {
                    swap_claim_update_dex_balance_func(
                        &amount_1_out,
                        total_token_0_in,
                        &old_balance_1,
                        &current_balance_1,
                    )
                },
            );
        });
    });

    write_to_json::<u64, _>(
        &bench_id,
        params,
        &params_name,
        "dex-swap-claim",
        &OperatorType::Atomic,
        64,
        vec![],
    );
}

#[cfg(not(feature = "gpu"))]
fn bench_swap_claim_throughput<FheType, F1, F2>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    bench_name: &str,
    type_name: &str,
    fn_name: &str,
    swap_claim_prepare_func: F1,
    swap_claim_update_dex_balance_func: F2,
) where
    FheType: FheEncrypt<u64, ClientKey> + Send + Sync,
    F1: for<'a> Fn(&'a FheType, &'a FheType, u64, u64, u64, u64) -> (FheType, FheType) + Sync,
    F2: for<'a> Fn(&'a FheType, u64, &'a FheType, &'a FheType) -> FheType + Sync,
{
    let mut rng = thread_rng();

    let params = client_key.computation_parameters();
    let params_name = params.name();

    for num_elems in [2, 6, 10] {
        group.throughput(Throughput::Elements(num_elems));
        let bench_id = format!(
            "{bench_name}::throughput::{fn_name}::{params_name}::{type_name}::{num_elems}_elems"
        );
        println!("{bench_id}");
        group.bench_with_input(&bench_id, &num_elems, |b, &num_elems| {
            let pending_0_in = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let pending_1_in = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let total_tokens_0_in = (0..num_elems).map(|_| rng.gen::<u64>()).collect::<Vec<_>>();
            let total_tokens_1_in = (0..num_elems).map(|_| rng.gen::<u64>()).collect::<Vec<_>>();
            let total_tokens_0_out = (0..num_elems).map(|_| rng.gen::<u64>()).collect::<Vec<_>>();
            let total_tokens_1_out = (0..num_elems).map(|_| rng.gen::<u64>()).collect::<Vec<_>>();
            let old_balances_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let old_balances_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let current_balances_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let current_balances_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();

            b.iter(|| {
                let (amounts_0_out, amounts_1_out): (Vec<_>, Vec<_>) = pending_0_in
                    .par_iter()
                    .zip(pending_1_in.par_iter())
                    .zip(total_tokens_0_in.par_iter())
                    .zip(total_tokens_1_in.par_iter())
                    .zip(total_tokens_0_out.par_iter())
                    .zip(total_tokens_1_out.par_iter())
                    .map(
                        |(
                            (
                                (
                                    ((pending_0_in, pending_1_in), total_token_0_in),
                                    total_token_1_in,
                                ),
                                total_token_0_out,
                            ),
                            total_token_1_out,
                        )| {
                            swap_claim_prepare_func(
                                pending_0_in,
                                pending_1_in,
                                *total_token_0_in,
                                *total_token_1_in,
                                *total_token_0_out,
                                *total_token_1_out,
                            )
                        },
                    )
                    .collect();
                rayon::join(
                    || {
                        amounts_0_out
                            .iter()
                            .zip(total_tokens_1_in.iter())
                            .zip(old_balances_0.iter())
                            .zip(current_balances_0.iter())
                            .for_each(
                                |(
                                    ((amount_0_out, total_token_1_in), old_balance_0),
                                    current_balance_0,
                                )| {
                                    let _ = swap_claim_update_dex_balance_func(
                                        amount_0_out,
                                        *total_token_1_in,
                                        old_balance_0,
                                        current_balance_0,
                                    );
                                },
                            )
                    },
                    || {
                        amounts_1_out
                            .iter()
                            .zip(total_tokens_0_in.iter())
                            .zip(old_balances_1.iter())
                            .zip(current_balances_1.iter())
                            .for_each(
                                |(
                                    ((amount_1_out, total_token_0_in), old_balance_1),
                                    current_balance_1,
                                )| {
                                    let _ = swap_claim_update_dex_balance_func(
                                        amount_1_out,
                                        *total_token_0_in,
                                        old_balance_1,
                                        current_balance_1,
                                    );
                                },
                            )
                    },
                );
            });
        });

        write_to_json::<u64, _>(
            &bench_id,
            params,
            &params_name,
            "dex-swap-claim",
            &OperatorType::Atomic,
            64,
            vec![],
        );
    }
}
#[cfg(feature = "gpu")]
fn cuda_bench_swap_claim_throughput<FheType, F1, F2>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    bench_name: &str,
    type_name: &str,
    fn_name: &str,
    swap_claim_prepare_func: F1,
    swap_claim_update_dex_balance_func: F2,
) where
    FheType: FheEncrypt<u64, ClientKey> + Send + Sync,
    F1: for<'a> Fn(&'a FheType, &'a FheType, u64, u64, u64, u64) -> (FheType, FheType) + Sync,
    F2: for<'a> Fn(&'a FheType, u64, &'a FheType, &'a FheType) -> FheType + Sync,
{
    let mut rng = thread_rng();
    let num_gpus = get_number_of_gpus() as u64;
    let compressed_server_key = CompressedServerKey::new(client_key);

    let sks_vec = (0..num_gpus)
        .map(|i| compressed_server_key.decompress_to_specific_gpu(GpuIndex::new(i as u32)))
        .collect::<Vec<_>>();
    let dex_balance_update_sks = compressed_server_key.decompress_to_gpu();

    let params = client_key.computation_parameters();
    let params_name = params.name();

    for num_elems in [num_gpus, 2 * num_gpus] {
        group.throughput(Throughput::Elements(num_elems));
        let bench_id = format!(
            "{bench_name}::throughput::{fn_name}::{params_name}::{type_name}::{num_elems}_elems"
        );
        println!("{bench_id}");
        group.bench_with_input(&bench_id, &num_elems, |b, &num_elems| {
            let pending_0_in = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let pending_1_in = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let total_tokens_0_in = (0..num_elems).map(|_| rng.gen::<u64>()).collect::<Vec<_>>();
            let total_tokens_1_in = (0..num_elems).map(|_| rng.gen::<u64>()).collect::<Vec<_>>();
            let total_tokens_0_out = (0..num_elems).map(|_| rng.gen::<u64>()).collect::<Vec<_>>();
            let total_tokens_1_out = (0..num_elems).map(|_| rng.gen::<u64>()).collect::<Vec<_>>();
            let old_balances_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let old_balances_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let current_balances_0 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let current_balances_1 = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let amounts_0_out = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();
            let amounts_1_out = (0..num_elems)
                .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                .collect::<Vec<_>>();

            let num_streams_per_gpu = 2.min(num_elems / num_gpus);
            let chunk_size = (num_elems / num_gpus) as usize;
            b.iter(|| {
                pending_0_in
                    .par_chunks(chunk_size)
                    .zip(pending_1_in.par_chunks(chunk_size))
                    .zip(total_tokens_0_in.par_chunks(chunk_size))
                    .zip(total_tokens_1_in.par_chunks(chunk_size))
                    .zip(total_tokens_0_out.par_chunks(chunk_size))
                    .zip(total_tokens_1_out.par_chunks(chunk_size))
                    .enumerate()
                    .for_each(
                        |(
                            i,
                            (
                                (
                                    (
                                        (
                                            (pending_0_in_gpu_i, pending_1_in_gpu_i),
                                            total_tokens_0_in_gpu_i,
                                        ),
                                        total_tokens_1_in_gpu_i,
                                    ),
                                    total_tokens_0_out_gpu_i,
                                ),
                                total_tokens_1_out_gpu_i,
                            ),
                        )| {
                            let stream_chunk_size =
                                pending_0_in_gpu_i.len() / num_streams_per_gpu as usize;
                            pending_0_in_gpu_i
                                .par_chunks(stream_chunk_size)
                                .zip(pending_1_in_gpu_i.par_chunks(stream_chunk_size))
                                .zip(total_tokens_0_in_gpu_i.par_chunks(stream_chunk_size))
                                .zip(total_tokens_1_in_gpu_i.par_chunks(stream_chunk_size))
                                .zip(total_tokens_0_out_gpu_i.par_chunks(stream_chunk_size))
                                .zip(total_tokens_1_out_gpu_i.par_chunks(stream_chunk_size))
                                .for_each(
                                    |(
                                        (
                                            (
                                                (
                                                    (pending_0_in_chunk, pending_1_in_chunk),
                                                    total_token_0_in_chunk,
                                                ),
                                                total_token_1_in_chunk,
                                            ),
                                            total_token_0_out_chunk,
                                        ),
                                        total_token_1_out_chunk,
                                    )| {
                                        // Set the server key for the current GPU
                                        set_server_key(sks_vec[i].clone());
                                        pending_0_in_chunk
                                            .iter()
                                            .zip(pending_1_in_chunk.iter())
                                            .zip(total_token_0_in_chunk.iter())
                                            .zip(total_token_1_in_chunk.iter())
                                            .zip(total_token_0_out_chunk.iter())
                                            .zip(total_token_1_out_chunk.iter())
                                            .for_each(
                                                |(
                                                    (
                                                        (
                                                            (
                                                                (pending_0_in, pending_1_in),
                                                                total_token_0_in,
                                                            ),
                                                            total_token_1_in,
                                                        ),
                                                        total_token_0_out,
                                                    ),
                                                    total_token_1_out,
                                                )| {
                                                    swap_claim_prepare_func(
                                                        pending_0_in,
                                                        pending_1_in,
                                                        *total_token_0_in,
                                                        *total_token_1_in,
                                                        *total_token_0_out,
                                                        *total_token_1_out,
                                                    );
                                                },
                                            )
                                    },
                                )
                        },
                    );
                rayon::join(
                    || {
                        set_server_key(dex_balance_update_sks.clone());
                        amounts_0_out
                            .iter()
                            .zip(total_tokens_1_in.iter())
                            .zip(old_balances_0.iter())
                            .zip(current_balances_0.iter())
                            .for_each(
                                |(
                                    ((amount_0_out, total_token_1_in), old_balance_0),
                                    current_balance_0,
                                )| {
                                    let _ = swap_claim_update_dex_balance_func(
                                        amount_0_out,
                                        *total_token_1_in,
                                        old_balance_0,
                                        current_balance_0,
                                    );
                                },
                            );
                    },
                    || {
                        set_server_key(dex_balance_update_sks.clone());
                        amounts_1_out
                            .iter()
                            .zip(total_tokens_0_in.iter())
                            .zip(old_balances_1.iter())
                            .zip(current_balances_1.iter())
                            .for_each(
                                |(
                                    ((amount_1_out, total_token_0_in), old_balance_1),
                                    current_balance_1,
                                )| {
                                    let _ = swap_claim_update_dex_balance_func(
                                        amount_1_out,
                                        *total_token_0_in,
                                        old_balance_1,
                                        current_balance_1,
                                    );
                                },
                            );
                    },
                );
            });
        });

        write_to_json::<u64, _>(
            &bench_id,
            params,
            &params_name,
            "dex-swap-claim",
            &OperatorType::Atomic,
            64,
            vec![],
        );
    }
}

#[cfg(feature = "pbs-stats")]
use crate::pbs_stats::print_swap_claim_prepare_pbs_counts;
#[cfg(feature = "pbs-stats")]
use crate::pbs_stats::print_swap_claim_update_dex_balance_pbs_counts;
#[cfg(feature = "pbs-stats")]
use crate::pbs_stats::print_swap_request_finalize_pbs_counts;
#[cfg(feature = "pbs-stats")]
use crate::pbs_stats::print_swap_request_update_dex_balance_pbs_counts;

#[cfg(not(feature = "gpu"))]
fn main() {
    let params = BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

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
        print_swap_request_update_dex_balance_pbs_counts(
            &cks,
            "FheUint64",
            "whitepaper",
            swap_request_update_dex_balance_whitepaper::<FheUint64>,
        );
        print_swap_request_update_dex_balance_pbs_counts(
            &cks,
            "FheUint64",
            "no_cmux",
            swap_request_update_dex_balance_no_cmux::<FheUint64>,
        );
        print_swap_request_finalize_pbs_counts(
            &cks,
            "FheUint64",
            swap_request_finalize::<FheUint64>,
        );
        print_swap_claim_prepare_pbs_counts(
            &cks,
            "FheUint64",
            swap_claim_prepare::<FheUint64, FheUint128>,
        );
        print_swap_claim_update_dex_balance_pbs_counts(
            &cks,
            "FheUint64",
            "whitepaper",
            swap_claim_update_dex_balance_whitepaper::<FheUint64>,
        );
        print_swap_claim_update_dex_balance_pbs_counts(
            &cks,
            "FheUint64",
            "no_cmux",
            swap_claim_update_dex_balance_no_cmux::<FheUint64>,
        );
    }

    match get_bench_type() {
        BenchmarkType::Latency => {
            let mut group = c.benchmark_group(bench_name);
            bench_swap_request_latency(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "swap_request::whitepaper",
                swap_request_update_dex_balance_whitepaper::<FheUint64>,
                swap_request_finalize::<FheUint64>,
            );
            bench_swap_request_latency(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "swap_request::no_cmux",
                swap_request_update_dex_balance_no_cmux::<FheUint64>,
                swap_request_finalize::<FheUint64>,
            );
            bench_swap_claim_latency(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "swap_claim::whitepaper",
                swap_claim_prepare::<FheUint64, FheUint128>,
                swap_claim_update_dex_balance_whitepaper::<FheUint64>,
            );
            bench_swap_claim_latency(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "swap_claim::no_cmux",
                swap_claim_prepare::<FheUint64, FheUint128>,
                swap_claim_update_dex_balance_no_cmux::<FheUint64>,
            );

            group.finish();
        }
        BenchmarkType::Throughput => {
            let mut group = c.benchmark_group(bench_name);
            bench_swap_request_throughput(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "swap_request::whitepaper",
                swap_request_update_dex_balance_whitepaper::<FheUint64>,
                swap_request_finalize::<FheUint64>,
            );
            bench_swap_request_throughput(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "swap_request::no_cmux",
                swap_request_update_dex_balance_no_cmux::<FheUint64>,
                swap_request_finalize::<FheUint64>,
            );
            bench_swap_claim_throughput(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "swap_claim::whitepaper",
                swap_claim_prepare::<FheUint64, FheUint128>,
                swap_claim_update_dex_balance_whitepaper::<FheUint64>,
            );
            bench_swap_claim_throughput(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "swap_claim::no_cmux",
                swap_claim_prepare::<FheUint64, FheUint128>,
                swap_claim_update_dex_balance_no_cmux::<FheUint64>,
            );
            group.finish();
        }
    };

    c.final_summary();
}

#[cfg(feature = "gpu")]
fn main() {
    let params = BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let config = ConfigBuilder::with_custom_parameters(params).build();
    let cks = ClientKey::generate(config);

    let mut c = Criterion::default().sample_size(10).configure_from_args();

    let bench_name = "hlapi::cuda::dex";

    // FheUint64 PBS counts
    // We don't run multiple times since every input is encrypted
    // PBS count is always the same
    #[cfg(feature = "pbs-stats")]
    {
        print_swap_request_update_dex_balance_pbs_counts(
            &cks,
            "FheUint64",
            "whitepaper",
            swap_request_update_dex_balance_whitepaper::<FheUint64>,
        );
        print_swap_request_update_dex_balance_pbs_counts(
            &cks,
            "FheUint64",
            "no_cmux",
            swap_request_update_dex_balance_no_cmux::<FheUint64>,
        );
        print_swap_request_finalize_pbs_counts(
            &cks,
            "FheUint64",
            swap_request_finalize::<FheUint64>,
        );
        print_swap_claim_prepare_pbs_counts(
            &cks,
            "FheUint64",
            swap_claim_prepare::<FheUint64, FheUint128>,
        );
        print_swap_claim_update_dex_balance_pbs_counts(
            &cks,
            "FheUint64",
            "whitepaper",
            swap_claim_update_dex_balance_whitepaper::<FheUint64>,
        );
        print_swap_claim_update_dex_balance_pbs_counts(
            &cks,
            "FheUint64",
            "no_cmux",
            swap_claim_update_dex_balance_no_cmux::<FheUint64>,
        );
    }

    match get_bench_type() {
        BenchmarkType::Latency => {
            let mut group = c.benchmark_group(bench_name);
            bench_swap_request_latency(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "swap_request::whitepaper",
                swap_request_update_dex_balance_whitepaper::<FheUint64>,
                swap_request_finalize::<FheUint64>,
            );
            bench_swap_request_latency(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "swap_request::no_cmux",
                swap_request_update_dex_balance_no_cmux::<FheUint64>,
                swap_request_finalize::<FheUint64>,
            );
            bench_swap_claim_latency(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "swap_claim::whitepaper",
                swap_claim_prepare::<FheUint64, FheUint128>,
                swap_claim_update_dex_balance_whitepaper::<FheUint64>,
            );
            bench_swap_claim_latency(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "swap_claim::no_cmux",
                swap_claim_prepare::<FheUint64, FheUint128>,
                swap_claim_update_dex_balance_no_cmux::<FheUint64>,
            );

            group.finish();
        }

        BenchmarkType::Throughput => {
            let mut group = c.benchmark_group(bench_name);
            cuda_bench_swap_request_throughput(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "swap_request::whitepaper",
                swap_request_update_dex_balance_whitepaper::<FheUint64>,
                swap_request_finalize::<FheUint64>,
            );
            cuda_bench_swap_request_throughput(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "swap_request::no_cmux",
                swap_request_update_dex_balance_no_cmux::<FheUint64>,
                swap_request_finalize::<FheUint64>,
            );
            cuda_bench_swap_claim_throughput(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "swap_claim::whitepaper",
                swap_claim_prepare::<FheUint64, FheUint128>,
                swap_claim_update_dex_balance_whitepaper::<FheUint64>,
            );
            cuda_bench_swap_claim_throughput(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "swap_claim::no_cmux",
                swap_claim_prepare::<FheUint64, FheUint128>,
                swap_claim_update_dex_balance_no_cmux::<FheUint64>,
            );
            group.finish();
        }
    };

    c.final_summary();
}

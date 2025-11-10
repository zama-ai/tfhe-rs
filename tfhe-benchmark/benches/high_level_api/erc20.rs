#[cfg(feature = "gpu")]
use benchmark::utilities::configure_gpu;
use benchmark::utilities::{get_bench_type, write_to_json, BenchmarkType, OperatorType};
use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion, Throughput};
use rand::prelude::*;
use rand::thread_rng;
#[cfg(not(feature = "hpu"))]
use rayon::prelude::*;
#[cfg(not(feature = "hpu"))]
use std::ops::Mul;
use std::ops::{Add, Sub};
#[cfg(feature = "gpu")]
use tfhe::core_crypto::gpu::get_number_of_gpus;
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
#[cfg(feature = "gpu")]
use tfhe::GpuIndex;
use tfhe::{set_server_key, ClientKey, CompressedServerKey, FheBool, FheUint64};

/// Transfer as written in the original FHEvm white-paper,
/// it uses a comparison to check if the sender has enough,
/// and cmuxes based on the comparison result
pub fn transfer_whitepaper<FheType>(
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

/// Parallel variant of [`transfer_whitepaper`].
pub fn par_transfer_whitepaper<FheType>(
    from_amount: &FheType,
    to_amount: &FheType,
    amount: &FheType,
) -> (FheType, FheType)
where
    FheType: Add<Output = FheType> + for<'a> FheOrd<&'a FheType> + Send + Sync,
    FheBool: IfThenElse<FheType>,
    for<'a> &'a FheType: Add<Output = FheType> + Sub<Output = FheType>,
{
    let has_enough_funds = (from_amount).ge(amount);

    let (new_to_amount, new_from_amount) = rayon::join(
        || {
            let new_to_amount = to_amount + amount;
            has_enough_funds.if_then_else(&new_to_amount, to_amount)
        },
        || {
            let new_from_amount = from_amount - amount;
            has_enough_funds.if_then_else(&new_from_amount, from_amount)
        },
    );

    (new_from_amount, new_to_amount)
}

/// This one also uses a comparison, but it leverages the 'boolean' multiplication
/// instead of cmuxes, so it is faster
#[cfg(all(feature = "gpu", not(feature = "hpu")))]
fn transfer_no_cmux<FheType>(
    from_amount: &FheType,
    to_amount: &FheType,
    amount: &FheType,
) -> (FheType, FheType)
where
    FheType: Add<Output = FheType> + CastFrom<FheBool> + for<'a> FheOrd<&'a FheType> + Send + Sync,
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

/// Parallel variant of [`transfer_no_cmux`].
#[cfg(not(feature = "hpu"))]
fn par_transfer_no_cmux<FheType>(
    from_amount: &FheType,
    to_amount: &FheType,
    amount: &FheType,
) -> (FheType, FheType)
where
    FheType: Add<Output = FheType> + CastFrom<FheBool> + for<'a> FheOrd<&'a FheType> + Send + Sync,
    FheBool: IfThenElse<FheType>,
    for<'a> &'a FheType:
        Add<Output = FheType> + Sub<Output = FheType> + Mul<FheType, Output = FheType>,
{
    let has_enough_funds = (from_amount).ge(amount);

    let amount = amount * FheType::cast_from(has_enough_funds);

    let (new_to_amount, new_from_amount) =
        rayon::join(|| to_amount + &amount, || from_amount - &amount);

    (new_from_amount, new_to_amount)
}

/// This one uses overflowing sub to remove the need for comparison
/// it also uses the 'boolean' multiplication
#[cfg(all(feature = "gpu", not(feature = "hpu")))]
fn transfer_overflow<FheType>(
    from_amount: &FheType,
    to_amount: &FheType,
    amount: &FheType,
) -> (FheType, FheType)
where
    FheType: CastFrom<FheBool> + for<'a> FheOrd<&'a FheType> + Send + Sync,
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

/// Parallel variant of [`transfer_overflow`].
#[cfg(not(feature = "hpu"))]
fn par_transfer_overflow<FheType>(
    from_amount: &FheType,
    to_amount: &FheType,
    amount: &FheType,
) -> (FheType, FheType)
where
    FheType: CastFrom<FheBool> + for<'a> FheOrd<&'a FheType> + Send + Sync,
    FheBool: IfThenElse<FheType>,
    for<'a> &'a FheType: Add<FheType, Output = FheType>
        + OverflowingSub<&'a FheType, Output = FheType>
        + Mul<FheType, Output = FheType>,
{
    let (new_from, did_not_have_enough) = (from_amount).overflowing_sub(amount);
    let did_not_have_enough = &did_not_have_enough;
    let had_enough_funds = !did_not_have_enough;

    let (new_from_amount, new_to_amount) = rayon::join(
        || did_not_have_enough.if_then_else(from_amount, &new_from),
        || to_amount + (amount * FheType::cast_from(had_enough_funds)),
    );

    (new_from_amount, new_to_amount)
}

/// This ones uses both overflowing_add/sub to check that both
/// the sender has enough funds, and the receiver will not overflow its balance
#[cfg(all(feature = "gpu", not(feature = "hpu")))]
fn transfer_safe<FheType>(
    from_amount: &FheType,
    to_amount: &FheType,
    amount: &FheType,
) -> (FheType, FheType)
where
    FheType: Send + Sync,
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

/// Parallel variant of [`transfer_safe`].
#[cfg(not(feature = "hpu"))]
fn par_transfer_safe<FheType>(
    from_amount: &FheType,
    to_amount: &FheType,
    amount: &FheType,
) -> (FheType, FheType)
where
    FheType: Send + Sync,
    for<'a> &'a FheType: OverflowingSub<&'a FheType, Output = FheType>
        + OverflowingAdd<&'a FheType, Output = FheType>,
    FheBool: IfThenElse<FheType>,
{
    let ((new_from, did_not_have_enough_funds), (new_to, did_not_have_enough_space)) = rayon::join(
        || (from_amount).overflowing_sub(amount),
        || (to_amount).overflowing_add(amount),
    );

    let something_not_ok = did_not_have_enough_funds | did_not_have_enough_space;

    let (new_from_amount, new_to_amount) = rayon::join(
        || something_not_ok.if_then_else(from_amount, &new_from),
        || something_not_ok.if_then_else(to_amount, &new_to),
    );

    (new_from_amount, new_to_amount)
}

#[cfg(feature = "hpu")]
/// This one use a dedicated IOp inside Hpu
fn transfer_hpu<FheType>(
    from_amount: &FheType,
    to_amount: &FheType,
    amount: &FheType,
) -> (FheType, FheType)
where
    FheType: FheHpu,
{
    use tfhe::tfhe_hpu_backend::prelude::hpu_asm;
    let src = HpuHandle {
        native: vec![from_amount, to_amount, amount],
        boolean: vec![],
        imm: vec![],
    };
    let mut res_handle = FheHpu::iop_exec(&hpu_asm::iop::IOP_ERC_20, src);
    // Iop erc_20 return new_from, new_to
    let new_to = res_handle.native.pop().unwrap();
    let new_from = res_handle.native.pop().unwrap();
    (new_from, new_to)
}

#[cfg(feature = "hpu")]
/// This one use a dedicated IOp inside Hpu
fn transfer_hpu_simd<FheType>(
    from_amount: &Vec<FheType>,
    to_amount: &Vec<FheType>,
    amount: &Vec<FheType>,
) -> Vec<FheType>
where
    FheType: FheHpu,
{
    use tfhe::tfhe_hpu_backend::prelude::hpu_asm;
    let src = HpuHandle {
        native: vec![from_amount, to_amount, amount]
            .into_iter()
            .flatten()
            .collect(),
        boolean: vec![],
        imm: vec![],
    };
    let res_handle = FheHpu::iop_exec(&hpu_asm::iop::IOP_ERC_20_SIMD, src);
    // Iop erc_20 return new_from, new_to
    let res = res_handle.native;
    res
}

#[cfg(all(feature = "pbs-stats", not(feature = "hpu")))]
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

        #[cfg(feature = "gpu")]
        configure_gpu(client_key);

        tfhe::reset_pbs_count();
        let (_, _) = transfer_func(&from_amount, &to_amount, &amount);
        let count = tfhe::get_pbs_count();

        println!("ERC20 transfer/{fn_name}::{type_name}: {count} PBS");

        let params = client_key.computation_parameters();
        let params_name = params.name();

        let test_name = if cfg!(feature = "gpu") {
            format!("hlapi::cuda::erc20::pbs_count::{fn_name}::{params_name}::{type_name}")
        } else {
            format!("hlapi::erc20::pbs_count::{fn_name}::{params_name}::{type_name}")
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
            params_name,
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
    FheType: FheWait,
    F: for<'a> Fn(&'a FheType, &'a FheType, &'a FheType) -> (FheType, FheType),
{
    #[cfg(feature = "gpu")]
    configure_gpu(client_key);

    let params = client_key.computation_parameters();
    let params_name = params.name();

    let bench_id = format!("{bench_name}::{fn_name}::{params_name}::{type_name}");
    println!("{bench_id}");
    c.bench_function(&bench_id, |b| {
        let mut rng = thread_rng();

        let from_amount = FheType::encrypt(rng.gen::<u64>(), client_key);
        let to_amount = FheType::encrypt(rng.gen::<u64>(), client_key);
        let amount = FheType::encrypt(rng.gen::<u64>(), client_key);

        b.iter(|| {
            let (new_from, new_to) = transfer_func(&from_amount, &to_amount, &amount);
            new_from.wait();
            criterion::black_box(new_from);
            new_to.wait();
            criterion::black_box(new_to);
        })
    });

    write_to_json::<u64, _>(
        &bench_id,
        params,
        params_name,
        "erc20-transfer",
        &OperatorType::Atomic,
        64,
        vec![],
    );
}

#[cfg(feature = "hpu")]
fn bench_transfer_latency_simd<FheType, F>(
    c: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    bench_name: &str,
    type_name: &str,
    fn_name: &str,
    transfer_func: F,
) where
    FheType: FheEncrypt<u64, ClientKey>,
    FheType: FheWait,
    F: for<'a> Fn(&'a Vec<FheType>, &'a Vec<FheType>, &'a Vec<FheType>) -> Vec<FheType>,
{
    use tfhe::tfhe_hpu_backend::prelude::hpu_asm;
    let hpu_simd_n = hpu_asm::iop::IOP_ERC_20_SIMD
        .format()
        .unwrap()
        .proto
        .src
        .len()
        / 3;

    let params = client_key.computation_parameters();
    let params_name = params.name();

    let bench_id = format!("{bench_name}::{fn_name}::{params_name}::{type_name}");
    println!("{bench_id}");
    c.bench_function(&bench_id, |b| {
        let mut rng = thread_rng();

        let mut from_amounts: Vec<FheType> = vec![];
        let mut to_amounts: Vec<FheType> = vec![];
        let mut amounts: Vec<FheType> = vec![];
        for _i in 0..hpu_simd_n {
            let from_amount = FheType::encrypt(rng.gen::<u64>(), client_key);
            let to_amount = FheType::encrypt(rng.gen::<u64>(), client_key);
            let amount = FheType::encrypt(rng.gen::<u64>(), client_key);
            from_amounts.push(from_amount);
            to_amounts.push(to_amount);
            amounts.push(amount);
        }

        b.iter(|| {
            let res = transfer_func(&from_amounts, &to_amounts, &amounts);
            for ct in res {
                ct.wait();
                criterion::black_box(ct);
            }
        })
    });

    write_to_json::<u64, _>(
        &bench_id,
        params,
        params_name,
        "erc20-simd-transfer",
        &OperatorType::Atomic,
        64,
        vec![],
    );
}

#[cfg(not(any(feature = "gpu", feature = "hpu")))]
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

    let params = client_key.computation_parameters();
    let params_name = params.name();

    for num_elems in [10, 100, 500] {
        group.throughput(Throughput::Elements(num_elems));
        let bench_id = format!(
            "{bench_name}::throughput::{fn_name}::{params_name}::{type_name}::{num_elems}_elems"
        );
        println!("{bench_id}");
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

        write_to_json::<u64, _>(
            &bench_id,
            params,
            &params_name,
            "erc20-transfer",
            &OperatorType::Atomic,
            64,
            vec![],
        );
    }
}

#[cfg(feature = "gpu")]
fn cuda_bench_transfer_throughput<FheType, F>(
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
    let num_gpus = get_number_of_gpus() as u64;
    let compressed_server_key = CompressedServerKey::new(client_key);

    let sks_vec = (0..num_gpus)
        .map(|i| compressed_server_key.decompress_to_specific_gpu(GpuIndex::new(i as u32)))
        .collect::<Vec<_>>();

    let params = client_key.computation_parameters();
    let params_name = params.name();

    // 200 * num_gpus seems to be enough for maximum throughput on 8xH100 SXM5
    let num_elems = 200 * num_gpus;

    group.throughput(Throughput::Elements(num_elems));
    let bench_id = format!(
        "{bench_name}::throughput::{fn_name}::{params_name}::{type_name}::{num_elems}_elems"
    );
    println!("{bench_id}");
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

        let num_streams_per_gpu = 8; // Hard coded stream value for FheUint64
        let chunk_size = (num_elems / num_gpus) as usize;

        b.iter(|| {
            from_amounts
                .par_chunks(chunk_size) // Split into chunks of num_gpus
                .zip(
                    to_amounts
                        .par_chunks(chunk_size)
                        .zip(amounts.par_chunks(chunk_size)),
                ) // Zip with the other data
                .enumerate() // Get the index for GPU
                .for_each(
                    |(i, (from_amount_gpu_i, (to_amount_gpu_i, amount_gpu_i)))| {
                        // Process chunks within each GPU
                        let stream_chunk_size = from_amount_gpu_i.len() / num_streams_per_gpu;
                        from_amount_gpu_i
                            .par_chunks(stream_chunk_size)
                            .zip(to_amount_gpu_i.par_chunks(stream_chunk_size))
                            .zip(amount_gpu_i.par_chunks(stream_chunk_size))
                            .for_each(|((from_amount_chunk, to_amount_chunk), amount_chunk)| {
                                // Set the server key for the current GPU
                                set_server_key(sks_vec[i].clone());
                                // Parallel iteration over the chunks of data
                                from_amount_chunk
                                    .iter()
                                    .zip(to_amount_chunk.iter().zip(amount_chunk.iter()))
                                    .for_each(|(from_amount, (to_amount, amount))| {
                                        transfer_func(from_amount, to_amount, amount);
                                    });
                            });
                    },
                );
        });
    });

    write_to_json::<u64, _>(
        &bench_id,
        params,
        &params_name,
        "erc20-transfer",
        &OperatorType::Atomic,
        64,
        vec![],
    );
}

#[cfg(feature = "hpu")]
fn hpu_bench_transfer_throughput<FheType, F>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    bench_name: &str,
    type_name: &str,
    fn_name: &str,
    transfer_func: F,
) where
    FheType: FheEncrypt<u64, ClientKey> + Send + Sync,
    FheType: FheWait,
    F: for<'a> Fn(&'a FheType, &'a FheType, &'a FheType) -> (FheType, FheType) + Sync,
{
    let mut rng = thread_rng();

    let params = client_key.computation_parameters();
    let params_name = params.name();

    for num_elems in [10, 100] {
        group.throughput(Throughput::Elements(num_elems));
        let bench_id = format!(
            "{bench_name}::throughput::{fn_name}::{params_name}::{type_name}::{num_elems}_elems"
        );
        println!("{bench_id}");
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
                let (last_new_from, last_new_to) = std::iter::zip(
                    from_amounts.iter(),
                    std::iter::zip(to_amounts.iter(), amounts.iter()),
                )
                .map(|(from_amount, (to_amount, amount))| {
                    transfer_func(from_amount, to_amount, amount)
                })
                .last()
                .unwrap();

                // Wait on last result to enforce all computation is over
                last_new_from.wait();
                criterion::black_box(last_new_from);
                last_new_to.wait();
                criterion::black_box(last_new_to);
            });
        });

        write_to_json::<u64, _>(
            &bench_id,
            params,
            &params_name,
            "erc20-transfer",
            &OperatorType::Atomic,
            64,
            vec![],
        );
    }
}

#[cfg(feature = "hpu")]
fn hpu_bench_transfer_throughput_simd<FheType, F>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    client_key: &ClientKey,
    bench_name: &str,
    type_name: &str,
    fn_name: &str,
    transfer_func: F,
) where
    FheType: FheEncrypt<u64, ClientKey> + Send + Sync,
    FheType: FheWait,
    F: for<'a> Fn(&'a Vec<FheType>, &'a Vec<FheType>, &'a Vec<FheType>) -> Vec<FheType> + Sync,
{
    use tfhe::tfhe_hpu_backend::prelude::hpu_asm;
    let hpu_simd_n = hpu_asm::iop::IOP_ERC_20_SIMD
        .format()
        .unwrap()
        .proto
        .src
        .len()
        / 3;
    let mut rng = thread_rng();

    let params = client_key.computation_parameters();
    let params_name = params.name();

    for num_elems in [2, 8] {
        let real_num_elems = num_elems * (hpu_simd_n as u64);
        group.throughput(Throughput::Elements(real_num_elems));
        let bench_id =
            format!("{bench_name}::throughput::{fn_name}::{params_name}::{type_name}::{real_num_elems}_elems");
        println!("{bench_id}");
        group.bench_with_input(&bench_id, &num_elems, |b, &num_elems| {
            let from_amounts = (0..num_elems)
                .map(|_| {
                    (0..hpu_simd_n)
                        .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                        .collect()
                })
                .collect::<Vec<_>>();
            let to_amounts = (0..num_elems)
                .map(|_| {
                    (0..hpu_simd_n)
                        .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                        .collect()
                })
                .collect::<Vec<_>>();
            let amounts = (0..num_elems)
                .map(|_| {
                    (0..hpu_simd_n)
                        .map(|_| FheType::encrypt(rng.gen::<u64>(), client_key))
                        .collect()
                })
                .collect::<Vec<_>>();

            b.iter(|| {
                let last_res_vec = std::iter::zip(
                    from_amounts.iter(),
                    std::iter::zip(to_amounts.iter(), amounts.iter()),
                )
                .map(|(from_amount, (to_amount, amount))| {
                    transfer_func(from_amount, to_amount, amount)
                })
                .last()
                .unwrap();

                // Wait on last result to enforce all computation is over
                for ct in last_res_vec {
                    ct.wait();
                    criterion::black_box(ct);
                }
            });
        });

        write_to_json::<u64, _>(
            &bench_id,
            params,
            &params_name,
            "erc20-simd-ransfer",
            &OperatorType::Atomic,
            64,
            vec![],
        );
    }
}

#[cfg(not(any(feature = "gpu", feature = "hpu")))]
fn main() {
    let params = benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let config = tfhe::ConfigBuilder::with_custom_parameters(params).build();
    let cks = ClientKey::generate(config);
    let compressed_sks = CompressedServerKey::new(&cks);

    let sks = compressed_sks.decompress();

    rayon::broadcast(|_| set_server_key(sks.clone()));
    set_server_key(sks);

    let mut c = Criterion::default().sample_size(10).configure_from_args();

    let bench_name = "hlapi::erc20";

    // FheUint64 PBS counts
    // We don't run multiple times since every input is encrypted
    // PBS count is always the same
    #[cfg(feature = "pbs-stats")]
    {
        use crate::pbs_stats::print_transfer_pbs_counts;
        print_transfer_pbs_counts(
            &cks,
            "FheUint64",
            "transfer::whitepaper",
            par_transfer_whitepaper::<FheUint64>,
        );
        print_transfer_pbs_counts(
            &cks,
            "FheUint64",
            "no_cmux",
            par_transfer_no_cmux::<FheUint64>,
        );
        print_transfer_pbs_counts(
            &cks,
            "FheUint64",
            "transfer::overflow",
            par_transfer_overflow::<FheUint64>,
        );
        print_transfer_pbs_counts(&cks, "FheUint64", "safe", par_transfer_safe::<FheUint64>);
    }

    match get_bench_type() {
        BenchmarkType::Latency => {
            let mut group = c.benchmark_group(bench_name);
            bench_transfer_latency(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::whitepaper",
                par_transfer_whitepaper::<FheUint64>,
            );
            bench_transfer_latency(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::no_cmux",
                par_transfer_no_cmux::<FheUint64>,
            );
            bench_transfer_latency(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::overflow",
                par_transfer_overflow::<FheUint64>,
            );
            bench_transfer_latency(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::safe",
                par_transfer_safe::<FheUint64>,
            );

            group.finish();
        }

        BenchmarkType::Throughput => {
            let mut group = c.benchmark_group(bench_name);
            bench_transfer_throughput(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::whitepaper",
                par_transfer_whitepaper::<FheUint64>,
            );
            bench_transfer_throughput(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::no_cmux",
                par_transfer_no_cmux::<FheUint64>,
            );
            bench_transfer_throughput(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::overflow",
                par_transfer_overflow::<FheUint64>,
            );
            bench_transfer_throughput(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::safe",
                par_transfer_safe::<FheUint64>,
            );

            group.finish();
        }
    };

    c.final_summary();
}

#[cfg(feature = "gpu")]
fn main() {
    let params =
    benchmark::params_aliases::BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let config = tfhe::ConfigBuilder::with_custom_parameters(params).build();
    let cks = ClientKey::generate(config);

    let mut c = Criterion::default().sample_size(10).configure_from_args();

    let bench_name = "hlapi::cuda::erc20";

    // FheUint64 PBS counts
    // We don't run multiple times since every input is encrypted
    // PBS count is always the same
    #[cfg(feature = "pbs-stats")]
    {
        use crate::pbs_stats::print_transfer_pbs_counts;
        print_transfer_pbs_counts(
            &cks,
            "FheUint64",
            "transfer::whitepaper",
            par_transfer_whitepaper::<FheUint64>,
        );
        print_transfer_pbs_counts(
            &cks,
            "FheUint64",
            "no_cmux",
            par_transfer_no_cmux::<FheUint64>,
        );
        print_transfer_pbs_counts(
            &cks,
            "FheUint64",
            "transfer::overflow",
            par_transfer_overflow::<FheUint64>,
        );
        print_transfer_pbs_counts(&cks, "FheUint64", "safe", par_transfer_safe::<FheUint64>);
    }

    match get_bench_type() {
        BenchmarkType::Latency => {
            let mut group = c.benchmark_group(bench_name);
            bench_transfer_latency(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::whitepaper",
                par_transfer_whitepaper::<FheUint64>,
            );
            bench_transfer_latency(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::no_cmux",
                par_transfer_no_cmux::<FheUint64>,
            );
            bench_transfer_latency(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::overflow",
                par_transfer_overflow::<FheUint64>,
            );
            bench_transfer_latency(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::safe",
                par_transfer_safe::<FheUint64>,
            );

            group.finish();
        }

        BenchmarkType::Throughput => {
            let mut group = c.benchmark_group(bench_name);
            cuda_bench_transfer_throughput(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::whitepaper",
                transfer_whitepaper::<FheUint64>,
            );
            cuda_bench_transfer_throughput(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::no_cmux",
                transfer_no_cmux::<FheUint64>,
            );
            cuda_bench_transfer_throughput(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::overflow",
                transfer_overflow::<FheUint64>,
            );
            cuda_bench_transfer_throughput(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::safe",
                transfer_safe::<FheUint64>,
            );
            group.finish();
        }
    };

    c.final_summary();
}
#[cfg(feature = "hpu")]
fn main() {
    let cks = {
        // Hpu is enable, start benchmark on Hpu hw accelerator
        use tfhe::tfhe_hpu_backend::prelude::*;
        use tfhe::Config;

        // Use environment variable to construct path to configuration file
        let config_path = ShellString::new(
            "${HPU_BACKEND_DIR}/config_store/${HPU_CONFIG}/hpu_config.toml".to_string(),
        );
        let hpu_device = HpuDevice::from_config(&config_path.expand());

        let config = Config::from_hpu_device(&hpu_device);
        let cks = ClientKey::generate(config);
        let compressed_sks = CompressedServerKey::new(&cks);

        set_server_key((hpu_device, compressed_sks));
        cks
    };

    let mut c = Criterion::default().sample_size(10).configure_from_args();

    let bench_name = "hlapi::hpu::erc20";

    match get_bench_type() {
        BenchmarkType::Latency => {
            let mut group = c.benchmark_group(bench_name);
            bench_transfer_latency(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::whitepaper",
                transfer_whitepaper::<FheUint64>,
            );
            // Erc20 optimized instruction only available on Hpu
            bench_transfer_latency(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::hpu_optim",
                transfer_hpu::<FheUint64>,
            );
            // Erc20 SIMD instruction only available on Hpu
            bench_transfer_latency_simd(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::hpu_simd",
                transfer_hpu_simd::<FheUint64>,
            );
            group.finish();
        }

        BenchmarkType::Throughput => {
            let mut group = c.benchmark_group(bench_name);
            hpu_bench_transfer_throughput(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::whitepaper",
                transfer_whitepaper::<FheUint64>,
            );
            // Erc20 optimized instruction only available on Hpu
            hpu_bench_transfer_throughput(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::hpu_optim",
                transfer_hpu::<FheUint64>,
            );
            // Erc20 SIMD instruction only available on Hpu
            hpu_bench_transfer_throughput_simd(
                &mut group,
                &cks,
                bench_name,
                "FheUint64",
                "transfer::hpu_simd",
                transfer_hpu_simd::<FheUint64>,
            );
            group.finish();
        }
    };

    c.final_summary();
}

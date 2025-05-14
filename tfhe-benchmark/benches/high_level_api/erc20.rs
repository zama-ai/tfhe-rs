#[cfg(feature = "gpu")]
use benchmark::params_aliases::BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
#[cfg(not(feature = "gpu"))]
use benchmark::params_aliases::BENCH_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
#[cfg(feature = "gpu")]
use benchmark::utilities::configure_gpu;
use benchmark::utilities::{write_to_json, OperatorType};
use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, Criterion, Throughput};
use rand::prelude::*;
use rayon::prelude::*;
use std::ops::{Add, Mul, Sub};
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
#[cfg(feature = "gpu")]
use tfhe::GpuIndex;
use tfhe::{set_server_key, ClientKey, CompressedServerKey, ConfigBuilder, FheBool, FheUint64};

/// Transfer as written in the original FHEvm white-paper,
/// it uses a comparison to check if the sender has enough,
/// and cmuxes based on the comparison result
pub fn transfer_whitepaper<FheType>(
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

    let (new_to_amount, new_from_amount) =
        rayon::join(|| to_amount + &amount, || from_amount - &amount);

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
        let mut rng = rand::rng();

        let from_amount = FheType::encrypt(rng.random::<u64>(), client_key);
        let to_amount = FheType::encrypt(rng.random::<u64>(), client_key);
        let amount = FheType::encrypt(rng.random::<u64>(), client_key);

        #[cfg(feature = "gpu")]
        configure_gpu(client_key);

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
    #[cfg(feature = "gpu")]
    configure_gpu(client_key);

    let bench_id = format!("{bench_name}::{fn_name}::{type_name}");
    c.bench_function(&bench_id, |b| {
        let mut rng = rand::rng();

        let from_amount = FheType::encrypt(rng.random::<u64>(), client_key);
        let to_amount = FheType::encrypt(rng.random::<u64>(), client_key);
        let amount = FheType::encrypt(rng.random::<u64>(), client_key);

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

#[cfg(not(feature = "gpu"))]
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
    let mut rng = rand::rng();

    for num_elems in [10, 100, 500] {
        group.throughput(Throughput::Elements(num_elems));
        let bench_id =
            format!("{bench_name}::throughput::{fn_name}::{type_name}::{num_elems}_elems");
        group.bench_with_input(&bench_id, &num_elems, |b, &num_elems| {
            let from_amounts = (0..num_elems)
                .map(|_| FheType::encrypt(rng.random::<u64>(), client_key))
                .collect::<Vec<_>>();
            let to_amounts = (0..num_elems)
                .map(|_| FheType::encrypt(rng.random::<u64>(), client_key))
                .collect::<Vec<_>>();
            let amounts = (0..num_elems)
                .map(|_| FheType::encrypt(rng.random::<u64>(), client_key))
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
    let mut rng = rand::rng();
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
            let from_amounts = (0..num_elems)
                .map(|_| FheType::encrypt(rng.random::<u64>(), client_key))
                .collect::<Vec<_>>();
            let to_amounts = (0..num_elems)
                .map(|_| FheType::encrypt(rng.random::<u64>(), client_key))
                .collect::<Vec<_>>();
            let amounts = (0..num_elems)
                .map(|_| FheType::encrypt(rng.random::<u64>(), client_key))
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
                                .for_each(
                                    |((from_amount_chunk, to_amount_chunk), amount_chunk)| {
                                        // Set the server key for the current GPU
                                        set_server_key(sks_vec[i].clone());
                                        // Parallel iteration over the chunks of data
                                        from_amount_chunk
                                            .iter()
                                            .zip(to_amount_chunk.iter().zip(amount_chunk.iter()))
                                            .for_each(|(from_amount, (to_amount, amount))| {
                                                transfer_func(from_amount, to_amount, amount);
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
use tfhe::core_crypto::gpu::get_number_of_gpus;

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

    let bench_name = "hlapi::erc20";

    // FheUint64 PBS counts
    // We don't run multiple times since every input is encrypted
    // PBS count is always the same
    #[cfg(feature = "pbs-stats")]
    {
        print_transfer_pbs_counts(
            &cks,
            "FheUint64",
            "transfer::whitepaper",
            transfer_whitepaper::<FheUint64>,
        );
        print_transfer_pbs_counts(&cks, "FheUint64", "no_cmux", transfer_no_cmux::<FheUint64>);
        print_transfer_pbs_counts(
            &cks,
            "FheUint64",
            "transfer::overflow",
            transfer_overflow::<FheUint64>,
        );
        print_transfer_pbs_counts(&cks, "FheUint64", "safe", transfer_safe::<FheUint64>);
    }

    // FheUint64 latency
    {
        let mut group = c.benchmark_group(bench_name);
        bench_transfer_latency(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "transfer::whitepaper",
            transfer_whitepaper::<FheUint64>,
        );
        bench_transfer_latency(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "transfer::no_cmux",
            transfer_no_cmux::<FheUint64>,
        );
        bench_transfer_latency(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "transfer::overflow",
            transfer_overflow::<FheUint64>,
        );
        bench_transfer_latency(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "transfer::safe",
            transfer_safe::<FheUint64>,
        );

        group.finish();
    }

    // FheUint64 Throughput
    {
        let mut group = c.benchmark_group(bench_name);
        bench_transfer_throughput(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "transfer::whitepaper",
            transfer_whitepaper::<FheUint64>,
        );
        bench_transfer_throughput(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "transfer::no_cmux",
            transfer_no_cmux::<FheUint64>,
        );
        bench_transfer_throughput(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "transfer::overflow",
            transfer_overflow::<FheUint64>,
        );
        bench_transfer_throughput(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "transfer::safe",
            transfer_safe::<FheUint64>,
        );

        group.finish();
    }

    c.final_summary();
}

#[cfg(feature = "gpu")]
fn main() {
    let params = BENCH_PARAM_GPU_MULTI_BIT_GROUP_4_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

    let config = ConfigBuilder::with_custom_parameters(params).build();
    let cks = ClientKey::generate(config);

    let mut c = Criterion::default().sample_size(10).configure_from_args();

    let bench_name = "hlapi::cuda::erc20";

    // FheUint64 PBS counts
    // We don't run multiple times since every input is encrypted
    // PBS count is always the same
    #[cfg(feature = "pbs-stats")]
    {
        print_transfer_pbs_counts(
            &cks,
            "FheUint64",
            "transfer::whitepaper",
            transfer_whitepaper::<FheUint64>,
        );
        print_transfer_pbs_counts(&cks, "FheUint64", "no_cmux", transfer_no_cmux::<FheUint64>);
        print_transfer_pbs_counts(
            &cks,
            "FheUint64",
            "transfer::overflow",
            transfer_overflow::<FheUint64>,
        );
        print_transfer_pbs_counts(&cks, "FheUint64", "safe", transfer_safe::<FheUint64>);
    }

    // FheUint64 latency
    {
        let mut group = c.benchmark_group(bench_name);
        bench_transfer_latency(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "transfer::whitepaper",
            transfer_whitepaper::<FheUint64>,
        );
        bench_transfer_latency(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "transfer::no_cmux",
            transfer_no_cmux::<FheUint64>,
        );
        bench_transfer_latency(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "transfer::overflow",
            transfer_overflow::<FheUint64>,
        );
        bench_transfer_latency(
            &mut group,
            &cks,
            bench_name,
            "FheUint64",
            "transfer::safe",
            transfer_safe::<FheUint64>,
        );

        group.finish();
    }

    // FheUint64 Throughput
    {
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

    c.final_summary();
}

//! How many transactions per second one GPU does, noise squashing included.
//!
//! Three spans over the workflow of [`benchmark::high_level_api::protocol`]: F1, F2, and the whole
//! transaction. The halves apart say where the time goes, and their serial sum predicts the whole,
//! so the gap with the measured `full_transaction` prices what the fused pipeline gains in overlap
//! and loses in memory. All three run at the same batch, otherwise nothing composes.
//!
//! The `no_rerand` variants price re-randomization by difference. They are not protocol figures.

use benchmark::high_level_api::protocol::{
    encrypt_compressed_inputs, encrypt_compressed_outputs, f1_decomp_transfer_comp,
    f2_decomp_sns_comp, full_transaction, generate_keys, par_transfer, ProtocolKeys,
    ReRandomization,
};
use benchmark::high_level_api::type_display::TypeDisplayer;
#[cfg(feature = "gpu")]
use benchmark::utilities::{get_bench_gpu_instances, get_param_type, ParamType};
use benchmark::utilities::{write_to_json, OperatorType};
use benchmark_spec::tfhe::hlapi::protocol::ProtocolKind;
use benchmark_spec::{
    get_bench_type, BenchmarkMetric, BenchmarkSpec, BenchmarkType, HlapiBench, OperandType,
    TypeName,
};
use criterion::{Criterion, Throughput};
use rand::thread_rng;
use rayon::prelude::*;
use std::hint::black_box;
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
#[cfg(feature = "gpu")]
use tfhe::GpuIndex;
use tfhe::{set_server_key, ClientKey, CompressedCiphertextList, FheUint64};

/// The whole question is about a single device. Other GPUs on the runner stay idle.
#[cfg(feature = "gpu")]
const BENCH_GPU: u32 = 0;

/// Matches the `hlapi-erc7984` GPU throughput benchmark, so F1 stays comparable to it. Lower it for
/// every shape at once if a run runs out of memory.
const DEFAULT_NUM_TRANSACTIONS: u64 = 800;

fn num_transactions() -> u64 {
    std::env::var("TFHE_RS_BENCH_PROTOCOL_TRANSACTIONS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_NUM_TRANSACTIONS)
}

/// What the device sees as concurrency. Overridable because finding the peak is the point.
#[cfg(feature = "gpu")]
const DEFAULT_NUM_STREAMS: usize = 16;

#[cfg(feature = "gpu")]
fn num_streams() -> usize {
    std::env::var("TFHE_RS_BENCH_PROTOCOL_STREAMS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_NUM_STREAMS)
}

/// Decompressed once for the run. On the GPU it carries the noise squashing key too, so a second
/// copy would cost device memory the transactions in flight need.
#[cfg(feature = "gpu")]
type BenchServerKey = tfhe::CudaServerKey;
#[cfg(not(feature = "gpu"))]
type BenchServerKey = tfhe::ServerKey;

/// Pinned to one device. `decompress_to_gpu` would spread the key over every visible GPU.
fn decompress_server_key(keys: &ProtocolKeys) -> BenchServerKey {
    #[cfg(feature = "gpu")]
    {
        keys.compressed_server_key
            .decompress_to_specific_gpu(GpuIndex::new(BENCH_GPU))
    }
    #[cfg(not(feature = "gpu"))]
    {
        keys.compressed_server_key.decompress()
    }
}

/// The rayon pool needs a key too, since `par_transfer` can hand a node to any worker.
fn install_server_key(sks: &BenchServerKey) {
    rayon::broadcast(|_| set_server_key(sks.clone()));
    set_server_key(sks.clone());
}

fn params_name(client_key: &ClientKey) -> String {
    let mut params = client_key.computation_parameters();
    params.set_deterministic_execution(false);
    params.name()
}

fn bench_spec_of(
    kind: ProtocolKind,
    params_name: &str,
    type_name: &dyn TypeName,
    bench_type: BenchmarkMetric,
    num_elements: Option<usize>,
) -> BenchmarkSpec {
    BenchmarkSpec::new_hlapi(
        HlapiBench::Protocol(kind),
        params_name,
        OperandType::CipherText,
        Some(type_name),
        bench_type,
        num_elements,
    )
}

/// One transaction alone on the device.
fn bench_latency(c: &mut Criterion, keys: &ProtocolKeys, kind: ProtocolKind) {
    let ProtocolKeys {
        client_key,
        compact_public_key,
        ..
    } = keys;
    let rerand = rerand_of(kind);
    let type_name = TypeDisplayer::<FheUint64>::default();
    let params_name = params_name(client_key);

    let mut group = c.benchmark_group(type_name.to_string());

    let bench_spec = bench_spec_of(
        kind,
        &params_name,
        &type_name,
        BenchmarkMetric::Latency,
        None,
    );
    let bench_id = bench_spec.to_string();

    let mut rng = thread_rng();
    let compressed_inputs = encrypt_compressed_inputs(client_key, &mut rng);
    let compressed_outputs = encrypt_compressed_outputs(client_key, &mut rng);

    group.bench_function(bench_id.as_str(), |b| match kind {
        ProtocolKind::DecompTransferComp | ProtocolKind::DecompTransferCompNoRerand => {
            b.iter(|| {
                let from_amount: FheUint64 = compressed_inputs.get(0).unwrap().unwrap();
                let to_amount: FheUint64 = compressed_inputs.get(1).unwrap().unwrap();
                let amount: FheUint64 = compressed_inputs.get(2).unwrap().unwrap();

                let (new_from, new_to) = par_transfer(
                    &from_amount,
                    &to_amount,
                    &amount,
                    compact_public_key,
                    rerand,
                );

                black_box(compress_pair(new_from, new_to));
            })
        }
        ProtocolKind::DecompNoiseSquashComp => b.iter(|| {
            black_box(f2_decomp_sns_comp(&compressed_outputs));
        }),
        ProtocolKind::FullTransaction | ProtocolKind::FullTransactionNoRerand => b.iter(|| {
            let from_amount: FheUint64 = compressed_inputs.get(0).unwrap().unwrap();
            let to_amount: FheUint64 = compressed_inputs.get(1).unwrap().unwrap();
            let amount: FheUint64 = compressed_inputs.get(2).unwrap().unwrap();

            let (new_from, new_to) = par_transfer(
                &from_amount,
                &to_amount,
                &amount,
                compact_public_key,
                rerand,
            );

            black_box(f2_decomp_sns_comp(&compress_pair(new_from, new_to)));
        }),
    });

    group.finish();

    write_to_json(
        &bench_spec,
        "protocol-transaction",
        &OperatorType::Atomic,
        64,
        vec![],
    );
}

fn compress_pair(new_from: FheUint64, new_to: FheUint64) -> CompressedCiphertextList {
    use tfhe::CompressedCiphertextListBuilder;

    CompressedCiphertextListBuilder::new()
        .push(new_from)
        .push(new_to)
        .build()
        .unwrap()
}

/// As many transactions in flight as the device takes.
fn bench_throughput(
    c: &mut Criterion,
    keys: &ProtocolKeys,
    sks: &BenchServerKey,
    kind: ProtocolKind,
) {
    let ProtocolKeys {
        client_key,
        compact_public_key,
        ..
    } = keys;
    let rerand = rerand_of(kind);
    let type_name = TypeDisplayer::<FheUint64>::default();
    let params_name = params_name(client_key);

    // Only the GPU path needs the handle. The CPU backend reads its thread local.
    #[cfg(not(feature = "gpu"))]
    let _ = sks;

    let num_elems = num_transactions();

    let mut group = c.benchmark_group(type_name.to_string());
    group.throughput(Throughput::Elements(num_elems));

    // One process per GPU reports for all of them, though each stays on its own device.
    #[cfg(feature = "gpu")]
    let reported_num_elems = num_elems * get_bench_gpu_instances().unwrap_or(1) as u64;
    #[cfg(not(feature = "gpu"))]
    let reported_num_elems = num_elems;

    let bench_spec = bench_spec_of(
        kind,
        &params_name,
        &type_name,
        BenchmarkMetric::Throughput,
        Some(reported_num_elems.try_into().unwrap()),
    );
    let bench_id = bench_spec.to_string();

    let mut rng = thread_rng();
    let inputs: Vec<CompressedCiphertextList> = (0..num_elems)
        .map(|_| match kind {
            ProtocolKind::DecompNoiseSquashComp => encrypt_compressed_outputs(client_key, &mut rng),
            _ => encrypt_compressed_inputs(client_key, &mut rng),
        })
        .collect();

    let run_one = |input: &CompressedCiphertextList| match kind {
        ProtocolKind::DecompTransferComp | ProtocolKind::DecompTransferCompNoRerand => {
            black_box(f1_decomp_transfer_comp(input, compact_public_key, rerand));
        }
        ProtocolKind::DecompNoiseSquashComp => {
            black_box(f2_decomp_sns_comp(input));
        }
        ProtocolKind::FullTransaction | ProtocolKind::FullTransactionNoRerand => {
            black_box(full_transaction(input, compact_public_key, rerand));
        }
    };

    group.bench_function(bench_id.as_str(), |b| {
        #[cfg(feature = "gpu")]
        {
            use benchmark::utilities::sync_bench_gpu_processes;

            // One chunk per stream. Concurrency comes from the stream count, not the batch size.
            let chunk_size = (inputs.len()).div_ceil(num_streams());

            sync_bench_gpu_processes();

            b.iter(|| {
                inputs.par_chunks(chunk_size).for_each(|chunk| {
                    // Cloning hands this worker its own CUDA streams.
                    set_server_key(sks.clone());

                    chunk.iter().for_each(run_one);
                });
            });
        }
        #[cfg(not(feature = "gpu"))]
        {
            b.iter(|| {
                inputs.par_iter().for_each(run_one);
            });
        }
    });

    group.finish();

    write_to_json(
        &bench_spec,
        "protocol-transaction",
        &OperatorType::Atomic,
        64,
        vec![],
    );
}

fn rerand_of(kind: ProtocolKind) -> ReRandomization {
    match kind {
        ProtocolKind::DecompTransferCompNoRerand | ProtocolKind::FullTransactionNoRerand => {
            ReRandomization::Off
        }
        _ => ReRandomization::On,
    }
}

/// PBS counts say how much of a transaction the noise squashing is, without trusting a wall clock.
///
/// CPU only, like the `hlapi-erc7984` counts. The GPU backend does not feed the `pbs-stats` counter
/// and would record zeros.
#[cfg(all(feature = "pbs-stats", not(feature = "gpu")))]
fn print_transaction_pbs_counts(keys: &ProtocolKeys) {
    let ProtocolKeys {
        client_key,
        compact_public_key,
        ..
    } = keys;
    let mut rng = thread_rng();
    let compressed_inputs = encrypt_compressed_inputs(client_key, &mut rng);

    let type_name = TypeDisplayer::<FheUint64>::default();
    let params_name = params_name(client_key);

    for (kind, count) in [
        (ProtocolKind::DecompTransferCompNoRerand, {
            tfhe::reset_pbs_count();
            let _ = f1_decomp_transfer_comp(
                &compressed_inputs,
                compact_public_key,
                ReRandomization::Off,
            );
            tfhe::get_pbs_count()
        }),
        (ProtocolKind::DecompTransferComp, {
            tfhe::reset_pbs_count();
            let _ = f1_decomp_transfer_comp(
                &compressed_inputs,
                compact_public_key,
                ReRandomization::On,
            );
            tfhe::get_pbs_count()
        }),
        (ProtocolKind::FullTransaction, {
            tfhe::reset_pbs_count();
            let _ = full_transaction(&compressed_inputs, compact_public_key, ReRandomization::On);
            tfhe::get_pbs_count()
        }),
    ] {
        println!("protocol/{kind}::{type_name}: {count} PBS");

        let bench_spec = bench_spec_of(
            kind,
            &params_name,
            &type_name,
            BenchmarkMetric::PbsCount,
            None,
        );
        write_to_json(&bench_spec, "pbs-count", &OperatorType::Atomic, 0, vec![]);
    }
}

/// Halves first, then the whole, which is the order a report reads in.
const KINDS: [ProtocolKind; 5] = [
    ProtocolKind::DecompTransferComp,
    ProtocolKind::DecompTransferCompNoRerand,
    ProtocolKind::DecompNoiseSquashComp,
    ProtocolKind::FullTransaction,
    ProtocolKind::FullTransactionNoRerand,
];

fn main() {
    #[cfg(feature = "gpu")]
    let meta_params = match get_param_type() {
        ParamType::Classical | ParamType::ClassicalDocumentation => {
            benchmark::params_aliases::BENCH_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128
        }
        _ => {
            benchmark::params_aliases::BENCH_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128
        }
    };
    #[cfg(not(feature = "gpu"))]
    let meta_params =
        benchmark::params_aliases::BENCH_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128;

    let keys = generate_keys(meta_params);
    let sks = decompress_server_key(&keys);
    install_server_key(&sks);

    let mut c = Criterion::default().sample_size(10).configure_from_args();

    #[cfg(all(feature = "pbs-stats", not(feature = "gpu")))]
    print_transaction_pbs_counts(&keys);

    for kind in KINDS {
        match get_bench_type() {
            BenchmarkType::Latency => bench_latency(&mut c, &keys, kind),
            BenchmarkType::Throughput => bench_throughput(&mut c, &keys, &sks, kind),
        }
    }

    c.final_summary();
}

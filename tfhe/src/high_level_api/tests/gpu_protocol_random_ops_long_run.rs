//! GPU drivers of the random operation sequence protocol stress test.
//!
//! The machinery, the operation pool and the reproducibility story live in
//! [`super::protocol_random_ops`]; this module only wires it to the GPU backend, over the same
//! four meta parameter configurations as the ERC-7984 transfer workflow test, and adds the
//! GPU specific drivers: the concurrent run, which keeps
//! `TFHE_RS_PROTOCOL_CONCURRENT_TRANSACTIONS` transactions in flight on a dedicated pool whose
//! workers each hold their own CUDA streams, and the forced coverage pass, which runs the whole
//! (operation, type, operand mode) matrix deterministically in one short run.
//!
//! Sizing a run:
//!
//! - `TFHE_RS_PROTOCOL_TRANSACTIONS` sets the transaction count, defaulting to the shared long
//!   run count.
//! - `TFHE_RS_PROTOCOL_DURATION_SECS` replaces the count with a wall clock budget, which is how
//!   the 24 hours soak runs are sized.
//!
//! Replaying a failure: a failing transaction writes a JSON report next to the test (or in
//! `TFHE_RS_PROTOCOL_FAILURE_DIR`); point `TFHE_RS_PROTOCOL_REPLAY` at it and run
//! `test_gpu_protocol_random_ops_replay` to re-execute that single transaction, keys included,
//! decrypting after every node to name the first diverging step.

use super::protocol_random_ops::{
    draw_transaction, evaluate_clear, load_failure_report,
    protocol_random_ops_forced_coverage_run, protocol_random_ops_run, replay_from_report,
    run_transaction_or_dump, Coverage, RandValues, RecentLog, RunIdentity, TransactionDescription,
};
use super::protocol_workflow_common::{generate_protocol_keys, num_transactions, run_duration};
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::integer::server_key::radix_parallel::tests_long_run::get_user_defined_seed;
use crate::shortint::parameters::test_params::{
    TEST_LEGACY_RERAND_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_LEGACY_RERAND_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128,
};
use crate::shortint::parameters::MetaParameters;
use crate::{clear_gpu_thread_locals, set_server_key, CompressedServerKey, Config, GpuIndex};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::time::Instant;
use tfhe_csprng::generators::DefaultRandomGenerator;
use tfhe_csprng::seeders::{Seed, Seeder};

/// The GPU every test runs on, pinned to a single device for the same reason as the transfer
/// workflow test: a key spread over every visible GPU would make the run profile depend on the
/// machine that picked up the job.
const TEST_GPU: u32 = 0;

/// Decompresses the server key to the test GPU and installs it on this thread and on the global
/// rayon pool, whose workers GPU operations are free to spill onto.
///
/// This installs a key on the workers of the global rayon pool, so the tests here have to run
/// one at a time, which is what the `test_protocol_random_ops_*_gpu` make targets ask for.
fn gpu_install_server_key(compressed_sks: &CompressedServerKey) {
    let gpu_sks = compressed_sks.decompress_to_specific_gpu(GpuIndex::new(TEST_GPU));
    rayon::broadcast(|_| set_server_key(gpu_sks.clone()));
    set_server_key(gpu_sks);
}

/// Multi bit compute parameters, re-randomization with a CPK derived from the compute key.
#[test]
fn test_gpu_protocol_random_ops_multi_bit() {
    protocol_random_ops_run(
        TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128,
        "TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128",
        "test_gpu_protocol_random_ops_multi_bit",
        gpu_install_server_key,
    );
}

/// Multi bit compute parameters, re-randomization through the legacy dedicated CPK and its
/// keyswitching key.
#[test]
fn test_gpu_protocol_random_ops_multi_bit_legacy_rerand() {
    protocol_random_ops_run(
        TEST_LEGACY_RERAND_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128,
        "TEST_LEGACY_RERAND_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128",
        "test_gpu_protocol_random_ops_multi_bit_legacy_rerand",
        gpu_install_server_key,
    );
}

/// Classical compute parameters, re-randomization with a CPK derived from the compute key.
#[test]
fn test_gpu_protocol_random_ops_classical() {
    protocol_random_ops_run(
        TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
        "TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128",
        "test_gpu_protocol_random_ops_classical",
        gpu_install_server_key,
    );
}

/// Classical compute parameters, re-randomization through the legacy dedicated CPK and its
/// keyswitching key.
#[test]
fn test_gpu_protocol_random_ops_classical_legacy_rerand() {
    protocol_random_ops_run(
        TEST_LEGACY_RERAND_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
        "TEST_LEGACY_RERAND_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128",
        "test_gpu_protocol_random_ops_classical_legacy_rerand",
        gpu_install_server_key,
    );
}

/// How many transactions the concurrent tests keep in flight, overridable through
/// `TFHE_RS_PROTOCOL_CONCURRENT_TRANSACTIONS` to tune the load to the device at hand, like the
/// concurrent transfer workflow test. The default is sized for the data center GPUs the soak
/// runs target (H100 class); push it to 16 there to saturate the device, or lower it on a
/// laptop class device, where a few transactions already fill the GPU.
const NUM_CONCURRENT_TRANSACTIONS: usize = 8;

fn num_concurrent_transactions() -> usize {
    std::env::var("TFHE_RS_PROTOCOL_CONCURRENT_TRANSACTIONS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(NUM_CONCURRENT_TRANSACTIONS)
}

/// The concurrent run: the same seeded setup, transaction stream and verification as the
/// sequential [`protocol_random_ops_run`], but transactions are evaluated in waves of
/// `num_concurrent_transactions` on a dedicated rayon pool, every worker holding a server key
/// with its own CUDA streams. Work stealing is free to move a transaction onto any thread, and
/// losing the thread to stream alignment is the point: it puts the whole pipeline, compression,
/// re-randomization, evaluation and noise squashing, under concurrent streams.
///
/// Every transaction installs its own seeded engine before encrypting, so the ciphertexts do not
/// depend on which thread picked the transaction up, and the stream is the same as the
/// sequential run of the same root seed: one failing transaction replays alone from its report,
/// sequentially.
fn protocol_random_ops_concurrent_run(
    meta_params: MetaParameters,
    params_name: &'static str,
    test_name: &str,
) {
    let seed = get_user_defined_seed().unwrap_or_else(|| {
        let mut seeder = crate::core_crypto::prelude::new_seeder();
        seeder.seed()
    });
    println!("{test_name}::seed = {}", seed.0);
    println!(
        "{test_name}: replay the whole run with TFHE_RS_LONGRUN_TESTS_SEED={}",
        seed.0
    );

    let mut root = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);
    let key_seed = root.seed();
    let setup_seed = root.seed();
    let data_seed = root.seed();

    let keys = generate_protocol_keys(Config::from(meta_params), key_seed, setup_seed);
    let gpu_sks = keys
        .compressed_sks
        .decompress_to_specific_gpu(GpuIndex::new(TEST_GPU));

    let concurrency = num_concurrent_transactions();
    println!("{test_name}: {concurrency} transactions in flight");

    // Two threads per in flight transaction, like the concurrent transfer test: the headroom
    // hosts whatever inner parallelism an operation spawns.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2 * concurrency)
        // Dropping a pool whose threads hold GPU thread locals needs this, rayon does not wait
        // for thread destruction and the CUDA driver is sensitive to the ordering.
        .exit_handler(|_| clear_gpu_thread_locals())
        .build()
        .unwrap();
    pool.broadcast(|_| set_server_key(gpu_sks.clone()));

    let identity = RunIdentity {
        params_name,
        key_seed,
        setup_seed,
    };
    let mut datagen = RandomGenerator::<DefaultRandomGenerator>::new(data_seed);

    let duration = run_duration();
    let count = num_transactions();
    match duration {
        Some(budget) => println!(
            "{test_name}: running for {} seconds of wall clock",
            budget.as_secs()
        ),
        None => println!("{test_name}: running {count} transactions"),
    }

    let start = Instant::now();
    let mut coverage = Coverage::default();
    // Sized to the wave: every transaction in flight is on disk before the wave is dispatched,
    // so a crash that takes the whole process down still leaves the executing graphs behind.
    let recent = RecentLog::new(10.max(concurrency));
    let mut index = 0usize;
    loop {
        let wave_len = match duration {
            Some(budget) => {
                if start.elapsed() >= budget {
                    break;
                }
                concurrency
            }
            None => {
                if index >= count {
                    break;
                }
                concurrency.min(count - index)
            }
        };

        // The wave is drawn on this thread, in index order, so the transaction stream is
        // identical to the sequential run of the same root seed, whatever the workers do.
        let wave: Vec<(usize, Seed, TransactionDescription)> = (0..wave_len)
            .map(|offset| {
                let transaction_seed = root.seed();
                let desc = draw_transaction(&mut datagen);
                if let Ok(evaluation) = evaluate_clear(&desc, &RandValues::new()) {
                    coverage.record(&evaluation);
                }
                recent.record(&desc, transaction_seed, index + offset, &identity);
                (index + offset, transaction_seed, desc)
            })
            .collect();

        pool.install(|| {
            wave.par_iter().for_each(|(index, transaction_seed, desc)| {
                run_transaction_or_dump(desc, *transaction_seed, *index, &keys, &identity, false);
            });
        });

        let before = index;
        index += wave_len;
        if index / 100 != before / 100 {
            println!(
                "{test_name}: {index} transactions, {} seconds elapsed",
                start.elapsed().as_secs()
            );
        }
    }

    println!("{test_name}: done, {index} transactions, signature coverage:");
    coverage.print();
}

/// Several transactions in flight, on the multi bit compute parameters.
#[test]
fn test_gpu_protocol_random_ops_concurrent_multi_bit() {
    protocol_random_ops_concurrent_run(
        TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128,
        "TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128",
        "test_gpu_protocol_random_ops_concurrent_multi_bit",
    );
}

/// Several transactions in flight, on the classical compute parameters.
#[test]
fn test_gpu_protocol_random_ops_concurrent_classical() {
    protocol_random_ops_concurrent_run(
        TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
        "TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128",
        "test_gpu_protocol_random_ops_concurrent_classical",
    );
}

/// The deterministic coverage pass: the whole (operation, type, operand mode) matrix in one
/// short run, on the production parameters, classical compute with message 2 carry 2.
#[test]
fn test_gpu_protocol_random_ops_forced_coverage() {
    protocol_random_ops_forced_coverage_run(
        TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
        "TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128",
        "test_gpu_protocol_random_ops_forced_coverage",
        gpu_install_server_key,
    );
}

/// Replays the failure report `TFHE_RS_PROTOCOL_REPLAY` points at, decrypting after every node.
/// Does nothing when the variable is not set, so the whole-module test filters stay usable.
#[test]
fn test_gpu_protocol_random_ops_replay() {
    let Ok(path) = std::env::var("TFHE_RS_PROTOCOL_REPLAY") else {
        println!("TFHE_RS_PROTOCOL_REPLAY is not set, nothing to replay");
        return;
    };
    replay_from_report(&load_failure_report(&path), gpu_install_server_key);
}

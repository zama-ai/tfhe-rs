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
//! - `TFHE_RS_PROTOCOL_TRANSACTIONS` sets the transaction count, defaulting to the shared long run
//!   count.
//! - `TFHE_RS_PROTOCOL_DURATION_SECS` replaces the count with a wall clock budget, which is how the
//!   24 hours soak runs are sized.
//!
//! Replaying a failure: a failing transaction writes a JSON report to
//! `TFHE_RS_PROTOCOL_FAILURE_DIR`, by default the working directory (`tfhe/` under `cargo test`)
//! that the run prints; point `TFHE_RS_PROTOCOL_REPLAY` at it and run
//! `test_gpu_protocol_random_ops_replay` to re-execute that single transaction, keys included,
//! decrypting after every node to name the first diverging step.

use super::protocol_random_ops::{
    draw_transaction, evaluate_clear, prepare_run, protocol_random_ops_forced_coverage_run,
    protocol_random_ops_run, replay_from_env, run_transaction_or_dump, Coverage, RandValues,
    RecentLog, RunLength, RunSetup, TransactionDescription,
};
use super::protocol_workflow_common::gpu::{
    install_server_key, num_concurrent_transactions, transaction_pool,
};
use crate::core_crypto::commons::math::random::RandomGenerator;
use std::any::Any;
use std::collections::VecDeque;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::Instant;
use tfhe_csprng::generators::DefaultRandomGenerator;
use tfhe_csprng::seeders::{Seed, Seeder};

// The parameter sets are passed by name: every driver resolves the constant through the same
// lookup the replay uses, so a run and its failure reports can never disagree on them.
const MULTI_BIT: &str =
    "TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128";
const MULTI_BIT_LEGACY_RERAND: &str =
    "TEST_LEGACY_RERAND_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128";
const CLASSICAL: &str = "TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128";
const CLASSICAL_LEGACY_RERAND: &str =
    "TEST_LEGACY_RERAND_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128";

/// Multi bit compute parameters, re-randomization with a CPK derived from the compute key.
#[test]
fn test_gpu_protocol_random_ops_multi_bit() {
    protocol_random_ops_run(
        MULTI_BIT,
        "test_gpu_protocol_random_ops_multi_bit",
        install_server_key,
    );
}

/// Multi bit compute parameters, re-randomization through the legacy dedicated CPK and its
/// keyswitching key.
#[test]
fn test_gpu_protocol_random_ops_multi_bit_legacy_rerand() {
    protocol_random_ops_run(
        MULTI_BIT_LEGACY_RERAND,
        "test_gpu_protocol_random_ops_multi_bit_legacy_rerand",
        install_server_key,
    );
}

/// Classical compute parameters, re-randomization with a CPK derived from the compute key.
#[test]
fn test_gpu_protocol_random_ops_classical() {
    protocol_random_ops_run(
        CLASSICAL,
        "test_gpu_protocol_random_ops_classical",
        install_server_key,
    );
}

/// Classical compute parameters, re-randomization through the legacy dedicated CPK and its
/// keyswitching key.
#[test]
fn test_gpu_protocol_random_ops_classical_legacy_rerand() {
    protocol_random_ops_run(
        CLASSICAL_LEGACY_RERAND,
        "test_gpu_protocol_random_ops_classical_legacy_rerand",
        install_server_key,
    );
}

/// How many transactions the concurrent tests keep in flight by default, see
/// [`num_concurrent_transactions`]. Sized for the data center GPUs the soak runs target (H100
/// class); push it to 16 there to saturate the device, or lower it on a laptop class device,
/// where a few transactions already fill the GPU.
const NUM_CONCURRENT_TRANSACTIONS: usize = 8;

/// The concurrent run: the same seeded setup, transaction stream and verification as the
/// sequential [`protocol_random_ops_run`], but `num_concurrent_transactions` transactions are
/// kept in flight on a dedicated rayon pool, every pool thread holding a server key with its own
/// CUDA streams. Work stealing is free to move a transaction onto any thread, and losing the
/// thread to stream alignment is the point: it puts the whole pipeline, compression,
/// re-randomization, evaluation and noise squashing, under concurrent streams.
///
/// The transactions go through a queue rather than in waves: each worker takes the next one as
/// soon as its previous one completes, so one long transaction (a collection at the size limit
/// costs about a hundred ordinary nodes) never leaves the other workers idle behind a barrier.
///
/// Every transaction installs its own seeded engine before encrypting, so the ciphertexts do not
/// depend on which thread picked the transaction up, and the stream is the same as the
/// sequential run of the same root seed: one failing transaction replays alone from its report,
/// sequentially.
///
/// The run stops at the first failure: nothing new is drawn and the queued transactions are
/// dropped unrun, only the ones already executing finish, then the failure is rethrown.
fn protocol_random_ops_concurrent_run(params_name: &str, test_name: &str) {
    // The same setup and seed stream as the sequential run, so the transaction stream is too.
    let RunSetup {
        keys,
        identity,
        mut root,
    } = prepare_run(params_name, test_name);
    let mut datagen = RandomGenerator::<DefaultRandomGenerator>::new(root.seed());

    let concurrency = num_concurrent_transactions(NUM_CONCURRENT_TRANSACTIONS);
    println!("{test_name}: {concurrency} transactions in flight");
    let pool = transaction_pool(concurrency, &keys.compressed_sks);

    let length = RunLength::from_env(test_name);

    let start = Instant::now();
    let mut coverage = Coverage::default();

    // Every transaction is written to a trace slot before it is queued, and its slot is reused
    // only once this thread has seen the transaction complete, so a crash that takes the whole
    // process down leaves every queued and executing graph on disk. At most `2 * concurrency`
    // transactions are queued or executing at once, so the extra slots always keep the most
    // recently completed graphs. Slots are reused in completion order: the next trace overwrites
    // the oldest one.
    let num_slots = 2 * concurrency + 10;
    let recent = RecentLog::new(num_slots, test_name);
    let mut completions = Completions {
        free_slots: (0..num_slots).collect(),
        completed: 0,
        failure: None,
    };

    // The workers only execute: they take the next queued transaction, run it and report how it
    // went. The slots, the progress and the failure handling all stay on this thread. The queue
    // is bounded, so this thread never draws more than `concurrency` transactions ahead.
    let (work_tx, work_rx) = mpsc::sync_channel::<QueuedTransaction>(concurrency);
    let work_rx = Mutex::new(work_rx);
    let (done_tx, done_rx) = mpsc::channel::<Completion>();
    // The one piece of state the workers share: raised by the first failing worker itself, so the
    // others stop starting queued transactions at once, without waiting for this thread to take
    // the failure in. It only gates work, no data travels through it.
    let stop = AtomicBool::new(false);

    let mut index = 0usize;
    std::thread::scope(|scope| {
        for _ in 0..concurrency {
            let done_tx = done_tx.clone();
            let (work_rx, pool, keys, identity, stop) = (&work_rx, &pool, &keys, &identity, &stop);
            // Workers are plain threads that hand each transaction to the pool, never long lived
            // pool jobs: a pool thread waiting inside a transaction may steal any pending pool
            // job, and stealing a never ending worker loop would stall that transaction for good.
            scope.spawn(move || loop {
                // The lock is held only while one worker waits for the next transaction.
                let next = work_rx.lock().unwrap().recv();
                let Ok((index, slot, transaction_seed, desc)) = next else {
                    break;
                };
                // After a failure, queued transactions are dropped unrun; their traces stay.
                if stop.load(Ordering::Relaxed) {
                    continue;
                }
                let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    pool.install(|| {
                        run_transaction_or_dump(
                            &desc,
                            transaction_seed,
                            index,
                            keys,
                            identity,
                            false,
                        );
                    });
                }));
                if outcome.is_err() {
                    stop.store(true, Ordering::Relaxed);
                }
                let _ = done_tx.send((slot, outcome));
            });
        }
        // Only the workers' clones are left, so the channel closes once they have all exited.
        drop(done_tx);

        // Transactions are drawn on this thread, in index order, so the stream is identical to
        // the sequential run of the same root seed, whatever order the workers complete in.
        loop {
            while let Ok(done) = done_rx.try_recv() {
                completions.record(done, test_name, start);
            }
            let keep_going = completions.failure.is_none() && length.allows(index, start);
            if !keep_going {
                break;
            }

            let transaction_seed = root.seed();
            let desc = draw_transaction(&mut datagen);
            if let Ok(evaluation) = evaluate_clear(&desc, &RandValues::new()) {
                coverage.record(&evaluation);
            }

            // Every slot can only be taken by a queued or executing transaction, or by a completed
            // one not taken in yet, so a completion is always on its way here.
            while completions.free_slots.is_empty() && completions.failure.is_none() {
                completions.record(done_rx.recv().unwrap(), test_name, start);
            }
            if completions.failure.is_some() {
                break;
            }
            let slot = completions.free_slots.pop_front().unwrap();
            recent.record_in_slot(&desc, transaction_seed, index, &identity, slot);
            work_tx
                .send((index, slot, transaction_seed, desc))
                .expect("the workers outlive the queue");
            index += 1;
        }

        // Closing the queue lets the workers exit once it is empty; after a failure they drop
        // whatever is still queued without running it.
        if completions.failure.is_some() {
            println!(
                "{test_name}: stopping at the first failure, waiting for the transactions still \
                 executing"
            );
        }
        drop(work_tx);
        for done in done_rx.iter() {
            completions.record(done, test_name, start);
        }
    });

    if let Some(payload) = completions.failure {
        std::panic::resume_unwind(payload);
    }

    println!("{test_name}: done, {index} transactions, signature coverage:");
    coverage.print();
}

/// A transaction waiting for a worker: its index, its trace slot, its encryption seed and its
/// graph.
type QueuedTransaction = (usize, usize, Seed, TransactionDescription);

/// What a worker reports back: the trace slot of the transaction it ran, and how the run went.
type Completion = (usize, std::thread::Result<()>);

/// The bookkeeping of the concurrent run, owned by the thread that draws the transactions.
struct Completions {
    /// The trace slots no queued or executing transaction holds, oldest trace first.
    free_slots: VecDeque<usize>,
    completed: usize,
    /// The first failure, rethrown once every worker has exited.
    failure: Option<Box<dyn Any + Send>>,
}

impl Completions {
    fn record(&mut self, (slot, outcome): Completion, test_name: &str, start: Instant) {
        match outcome {
            Ok(()) => {
                self.free_slots.push_back(slot);
                self.completed += 1;
                if self.completed.is_multiple_of(100) {
                    println!(
                        "{test_name}: {} transactions, {} seconds elapsed",
                        self.completed,
                        start.elapsed().as_secs()
                    );
                }
            }
            // The slot of a failing transaction is never reused, its trace stays on disk.
            Err(payload) => {
                self.failure.get_or_insert(payload);
            }
        }
    }
}

/// Several transactions in flight, on the multi bit compute parameters.
#[test]
fn test_gpu_protocol_random_ops_concurrent_multi_bit() {
    protocol_random_ops_concurrent_run(
        MULTI_BIT,
        "test_gpu_protocol_random_ops_concurrent_multi_bit",
    );
}

/// Several transactions in flight, on the classical compute parameters.
#[test]
fn test_gpu_protocol_random_ops_concurrent_classical() {
    protocol_random_ops_concurrent_run(
        CLASSICAL,
        "test_gpu_protocol_random_ops_concurrent_classical",
    );
}

/// The deterministic coverage pass: the whole (operation, type, operand mode) matrix in one
/// short run, on the production parameters, classical compute with message 2 carry 2.
#[test]
fn test_gpu_protocol_random_ops_forced_coverage() {
    protocol_random_ops_forced_coverage_run(
        CLASSICAL,
        "test_gpu_protocol_random_ops_forced_coverage",
        install_server_key,
    );
}

/// Replays the failure report `TFHE_RS_PROTOCOL_REPLAY` points at, decrypting after every node.
/// Does nothing when the variable is not set, so the whole-module test filters stay usable.
#[test]
fn test_gpu_protocol_random_ops_replay() {
    replay_from_env(install_server_key);
}

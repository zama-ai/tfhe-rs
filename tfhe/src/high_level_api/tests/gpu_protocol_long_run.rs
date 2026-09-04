//! End to end test of the confidential transaction workflow used by the Zama protocol, running
//! on the GPU backend.
//!
//! The computation itself is the ERC-7984 whitepaper `transfer`, the very same graph that is
//! benchmarked for GPU latency in `tfhe-benchmark` (`par_transfer_whitepaper`), but here every
//! node of the graph re-randomizes its own operands before being evaluated, and the ciphertexts
//! travel through the compression and noise squashing stages the protocol relies on.
//!
//! One iteration is one transaction:
//!
//! ```text
//! encrypt(from_balance, to_balance, amount) : 3 x u64
//!   -> compress                        (ciphertexts are stored compressed)
//!   -> decompress                      (loaded before evaluation)
//!   -> transfer graph, each node re-randomizing its operands first
//!   -> compress   (new_from, new_to)   (results are stored back compressed)
//!   -> decompress
//!   -> noise squash                    (64 bit -> 128 bit, before threshold decryption)
//!   -> compress   (128 bit)
//!   -> decompress (128 bit)
//!   -> decrypt
//! ```
//!
//! The two decrypted outputs are compared against the transfer computed in the clear on the
//! original inputs. Every transaction is additionally evaluated twice to check that the whole
//! re-randomize + evaluate sequence is deterministic, which the protocol needs to have several
//! coprocessors agree on the same ciphertexts.
//!
//! Two shapes are tested: one transaction at a time, over every parameter set, and several
//! transactions at a time on the classical parameters, to put the device under load.

use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::high_level_api::prelude::*;
use crate::integer::server_key::radix_parallel::tests_long_run::{
    get_long_test_iterations, get_user_defined_seed,
};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::test_params::{
    TEST_LEGACY_RERAND_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_LEGACY_RERAND_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128,
};
use crate::shortint::parameters::MetaParameters;
use crate::{
    clear_gpu_thread_locals, set_server_key, ClientKey, CompactPublicKey,
    CompressedCiphertextListBuilder, CompressedServerKey,
    CompressedSquashedNoiseCiphertextListBuilder, Config, FheBool, FheUint64, GpuIndex,
    ReRandomizationContext, ReRandomizationSeedGen, SquashedNoiseFheUint,
};
use rayon::iter::{IndexedParallelIterator, ParallelIterator};
use rayon::slice::ParallelSlice;
use std::sync::atomic::{AtomicUsize, Ordering};
use tfhe_csprng::generators::DefaultRandomGenerator;
use tfhe_csprng::seeders::{Seed, Seeder};

/// Domain separator fed to the re-randomization seed generator.
const RERAND_DOMAIN_SEPARATOR: [u8; 8] = *b"TFHE_Rrd";
/// Domain separator used to generate the compact public key encryptions of zero.
const CPK_ENCRYPTION_DOMAIN_SEPARATOR: [u8; 8] = *b"TFHE_Enc";
/// Size of the metadata attached to an input ciphertext, simulating the 256 bits hash that ties
/// an input to its origin.
const METADATA_LEN: usize = 256 / 8;

/// How many transactions a test runs.
///
/// Defaults to the shared long run count, which the `TFHE_RS_TEST_LONG_TESTS_MINIMAL` environment
/// variable already shortens. The dedicated stress target overrides it to size a run to a wall
/// clock budget of its own.
fn num_transactions() -> usize {
    std::env::var("TFHE_RS_PROTOCOL_TRANSACTIONS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or_else(get_long_test_iterations)
}

/// The GPU every test runs on.
///
/// Pinned to a single device on purpose: `decompress_to_gpu` would spread the server key over every
/// visible GPU, which would make the run time and the memory profile depend on the machine that
/// picked up the job. On a multi GPU runner the other devices are simply left idle.
const TEST_GPU: u32 = 0;

/// How many transactions the concurrent test keeps in flight, overridable to tune the load to the
/// device at hand.
const NUM_CONCURRENT_TRANSACTIONS: usize = 4;

fn num_concurrent_transactions() -> usize {
    std::env::var("TFHE_RS_PROTOCOL_CONCURRENT_TRANSACTIONS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(NUM_CONCURRENT_TRANSACTIONS)
}

/// Opcode of a node of the transfer graph. The protocol mixes only this opcode, as big endian
/// bytes, into the re-randomization context of a node. The values below stand in for the
/// protocol's own opcode numbering: what the workflow relies on is that each operation of the
/// graph has its own.
type NodeOpcode = u32;

const OPCODE_GE: NodeOpcode = 1;
const OPCODE_IF_THEN_ELSE: NodeOpcode = 2;
const OPCODE_ADD: NodeOpcode = 3;
const OPCODE_SUB: NodeOpcode = 4;

/// Opens the re-randomization context of a single graph node.
///
/// The seeds of a node only depend on the node opcode and on the node operands, so two
/// coprocessors evaluating the same node of the same transaction derive the same seeds.
fn node_re_randomization_context(opcode: NodeOpcode) -> ReRandomizationContext {
    ReRandomizationContext::new(
        RERAND_DOMAIN_SEPARATOR,
        [opcode.to_be_bytes().as_slice()],
        CPK_ENCRYPTION_DOMAIN_SEPARATOR,
    )
}

/// Installs a re-seeded encryption engine on the calling thread.
///
/// Key generation and encryption both draw from this thread local engine, so seeding it is what
/// makes a failure reproducible: with `TFHE_RS_LONGRUN_TESTS_SEED` set, a run replays the same
/// keys and the same ciphertexts, not merely the same clear inputs. Re-randomization then follows,
/// since its seeds are derived from the ciphertext bytes.
fn install_seeded_engine(seed: Seed) {
    let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);
    let engine = ShortintEngine::new_from_seeder(&mut seeder);
    ShortintEngine::with_thread_local_mut(|local_engine| {
        let _ = std::mem::replace(local_engine, engine);
    });
}

/// Draws `N` deterministic bytes, used for the input metadata.
fn random_bytes<const N: usize>(
    datagen: &mut DeterministicSeeder<DefaultRandomGenerator>,
) -> [u8; N] {
    let mut out = [0u8; N];
    for chunk in out.chunks_mut(core::mem::size_of::<u128>()) {
        let bytes = datagen.seed().0.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    out
}

/// Draws the transfer amount.
///
/// `affordable` picks between an amount the sender can cover, which makes the transfer go through,
/// and one strictly above its balance, which makes it rejected. Both branches consume a single
/// seed, so the transaction stream stays the same whichever is taken.
///
/// A `from_amount` of `u64::MAX` has no amount above it, so it falls back to an affordable one.
/// That is a 2^-64 event, the branch only exists to keep the arithmetic total.
fn draw_amount(from_amount: u64, affordable: bool, seed: u64) -> u64 {
    let above_balance = u64::MAX - from_amount;

    if affordable || above_balance == 0 {
        // In `[0, from_amount]`, draining the balance exactly included.
        seed % from_amount.saturating_add(1)
    } else {
        // In `[from_amount + 1, u64::MAX]`.
        from_amount + 1 + seed % above_balance
    }
}

/// The clear side of one transaction, drawn before anything is encrypted.
struct Transaction {
    from_amount: u64,
    to_amount: u64,
    amount: u64,
    metadata: [[u8; METADATA_LEN]; 3],
}

impl Transaction {
    /// Draws transaction number `index`.
    ///
    /// We want an 80/20 split: four transfers out of five are affordable and go through, one out
    /// of five is rejected for insufficient funds. Most of the protocol's traffic is successful
    /// transfers, but the rejected branch has to stay well covered.
    fn draw(index: usize, datagen: &mut DeterministicSeeder<DefaultRandomGenerator>) -> Self {
        let from_amount = datagen.seed().0 as u64;
        let to_amount = datagen.seed().0 as u64;
        let amount = draw_amount(
            from_amount,
            !index.is_multiple_of(5),
            datagen.seed().0 as u64,
        );
        let metadata = core::array::from_fn(|_| random_bytes::<METADATA_LEN>(datagen));

        Self {
            from_amount,
            to_amount,
            amount,
            metadata,
        }
    }

    /// The ERC-7984 whitepaper transfer, in the clear.
    fn expected_result(&self) -> (u64, u64) {
        let amount_to_transfer = if self.from_amount >= self.amount {
            self.amount
        } else {
            0
        };

        (
            self.from_amount.wrapping_sub(amount_to_transfer),
            self.to_amount.wrapping_add(amount_to_transfer),
        )
    }
}

/// Re-randomizes one operand of a graph node, with its own seed taken from the node seed stream.
fn re_randomize_operand<T: ReRandomize>(
    ct: &mut T,
    cpk: &CompactPublicKey,
    seed_gen: &mut ReRandomizationSeedGen,
) {
    // Handing over the compact public key covers both re-randomization modes: a server key built
    // on the legacy dedicated CPK uses it along its keyswitching key, a server key holding a CPK
    // derived from the compute key ignores it in favor of the derived one.
    ct.re_randomize(cpk, seed_gen.next_seed().unwrap()).unwrap();
}

/// The ERC-7984 whitepaper transfer, as a graph of four nodes:
///
/// ```text
/// n1: has_enough_funds   = ge(from_amount, amount)
/// n2: amount_to_transfer = if_then_else(has_enough_funds, amount, 0)
/// n3: new_to_amount      = add(to_amount, amount_to_transfer)   \
///                                                               |- evaluated in parallel
/// n4: new_from_amount    = sub(from_amount, amount_to_transfer)  /
/// ```
///
/// Every node applies the protocol's pre-evaluation step to its own operands: absorb each non
/// scalar operand into the node context in operand order, finalize the context once, then
/// re-randomize each of those operands with its own seed, in that same order. No node of this
/// graph takes a scalar operand, so every operand goes through both loops. Operands are cloned
/// per node on purpose: a value feeding several nodes is re-randomized independently in each of
/// them, exactly like a handle read several times by a transaction would be.
#[allow(
    clippy::redundant_clone,
    reason = "every node owns and re-randomizes its own copy of its operands, including the nodes \
              that happen to be the last reader of a value"
)]
fn run_transfer_graph(
    from_amount: &FheUint64,
    to_amount: &FheUint64,
    amount: &FheUint64,
    cpk: &CompactPublicKey,
) -> (FheUint64, FheUint64) {
    // n1: has_enough_funds = from_amount >= amount
    let has_enough_funds = {
        let mut lhs = from_amount.clone();
        let mut rhs = amount.clone();

        let mut ctx = node_re_randomization_context(OPCODE_GE);
        ctx.add_ciphertext(&lhs);
        ctx.add_ciphertext(&rhs);
        let mut seed_gen = ctx.finalize();

        re_randomize_operand(&mut lhs, cpk, &mut seed_gen);
        re_randomize_operand(&mut rhs, cpk, &mut seed_gen);

        lhs.ge(&rhs)
    };

    // n2: amount_to_transfer = has_enough_funds ? amount : 0
    //
    // The zero is a ciphertext operand, not a scalar: the GPU if_then_else rejects clear inputs,
    // so it is trivially encrypted and goes through the context and the re-randomization like any
    // other operand.
    let amount_to_transfer = {
        let mut condition: FheBool = has_enough_funds.clone();
        let mut then_value = amount.clone();
        let mut else_value = FheUint64::encrypt_trivial(0u64);

        let mut ctx = node_re_randomization_context(OPCODE_IF_THEN_ELSE);
        ctx.add_ciphertext(&condition);
        ctx.add_ciphertext(&then_value);
        ctx.add_ciphertext(&else_value);
        let mut seed_gen = ctx.finalize();

        re_randomize_operand(&mut condition, cpk, &mut seed_gen);
        re_randomize_operand(&mut then_value, cpk, &mut seed_gen);
        re_randomize_operand(&mut else_value, cpk, &mut seed_gen);

        condition.select(&then_value, &else_value)
    };

    // n3 and n4 both depend on n2 only, so the protocol evaluates them in parallel and so does
    // the test. Each node derives its seeds from its own opcode and its own operands, nothing is
    // shared between the two, so running them concurrently cannot change either result.
    let (new_to_amount, new_from_amount) = rayon::join(
        || {
            // n3: new_to_amount = to_amount + amount_to_transfer
            let mut lhs = to_amount.clone();
            let mut rhs = amount_to_transfer.clone();

            let mut ctx = node_re_randomization_context(OPCODE_ADD);
            ctx.add_ciphertext(&lhs);
            ctx.add_ciphertext(&rhs);
            let mut seed_gen = ctx.finalize();

            re_randomize_operand(&mut lhs, cpk, &mut seed_gen);
            re_randomize_operand(&mut rhs, cpk, &mut seed_gen);

            &lhs + &rhs
        },
        || {
            // n4: new_from_amount = from_amount - amount_to_transfer
            let mut lhs = from_amount.clone();
            let mut rhs = amount_to_transfer.clone();

            let mut ctx = node_re_randomization_context(OPCODE_SUB);
            ctx.add_ciphertext(&lhs);
            ctx.add_ciphertext(&rhs);
            let mut seed_gen = ctx.finalize();

            re_randomize_operand(&mut lhs, cpk, &mut seed_gen);
            re_randomize_operand(&mut rhs, cpk, &mut seed_gen);

            &lhs - &rhs
        },
    );

    (new_from_amount, new_to_amount)
}

/// Runs one transaction through the whole protocol workflow and checks it against the clear
/// result. `index` only shows up in the assertion messages.
///
/// Expects a server key to be set on the calling thread, and on any thread that could steal the
/// inner `rayon::join` of the transfer graph.
fn run_one_transaction(
    transaction: &Transaction,
    index: usize,
    cks: &ClientKey,
    cpk: &CompactPublicKey,
) {
    let Transaction {
        from_amount: clear_from_amount,
        to_amount: clear_to_amount,
        amount: clear_amount,
        metadata,
    } = transaction;
    let (clear_from_amount, clear_to_amount, clear_amount) =
        (*clear_from_amount, *clear_to_amount, *clear_amount);

    let (expected_new_from, expected_new_to) = transaction.expected_result();

    // The user encrypts the transaction inputs, each one tied to its origin by some metadata.
    let mut from_amount = FheUint64::encrypt(clear_from_amount, cks);
    let mut to_amount = FheUint64::encrypt(clear_to_amount, cks);
    let mut amount = FheUint64::encrypt(clear_amount, cks);
    from_amount
        .re_randomization_metadata_mut()
        .set_data(&metadata[0]);
    to_amount
        .re_randomization_metadata_mut()
        .set_data(&metadata[1]);
    amount
        .re_randomization_metadata_mut()
        .set_data(&metadata[2]);

    // Inputs are stored compressed.
    let compressed_inputs = CompressedCiphertextListBuilder::new()
        .push(from_amount)
        .push(to_amount)
        .push(amount)
        .build()
        .unwrap();

    // And loaded back before the transaction is evaluated.
    let from_amount: FheUint64 = compressed_inputs.get(0).unwrap().unwrap();
    let to_amount: FheUint64 = compressed_inputs.get(1).unwrap().unwrap();
    let amount: FheUint64 = compressed_inputs.get(2).unwrap().unwrap();

    for (operand, (ct, expected)) in [&from_amount, &to_amount, &amount]
        .into_iter()
        .zip(metadata.iter())
        .enumerate()
    {
        assert_eq!(
            ct.re_randomization_metadata().data(),
            expected,
            "{index}: input {operand} lost its re-randomization metadata through compression",
        );
    }

    let decrypted_from: u64 = from_amount.decrypt(cks);
    let decrypted_to: u64 = to_amount.decrypt(cks);
    let decrypted_amount: u64 = amount.decrypt(cks);
    assert_eq!(
        (decrypted_from, decrypted_to, decrypted_amount),
        (clear_from_amount, clear_to_amount, clear_amount),
        "{index}: inputs changed value through compression/decompression",
    );

    // The transaction itself.
    let (new_from_amount, new_to_amount) =
        run_transfer_graph(&from_amount, &to_amount, &amount, cpk);

    let decrypted_new_from: u64 = new_from_amount.decrypt(cks);
    let decrypted_new_to: u64 = new_to_amount.decrypt(cks);
    assert_eq!(
        decrypted_new_from, expected_new_from,
        "{index}: invalid transfer result on from amount, \
         from: {clear_from_amount}, to: {clear_to_amount}, amount: {clear_amount}",
    );
    assert_eq!(
        decrypted_new_to, expected_new_to,
        "{index}: invalid transfer result on to amount, \
         from: {clear_from_amount}, to: {clear_to_amount}, amount: {clear_amount}",
    );

    // Re-randomization seeds only depend on the node opcode and on the node operands, so
    // evaluating the same transaction again has to produce the very same ciphertexts. The GPU
    // backend drops the `deterministic_execution` parameter flag, its bootstraps are deterministic
    // by construction, so this holds for every parameter set below.
    {
        let (new_from_amount_bis, new_to_amount_bis) =
            run_transfer_graph(&from_amount, &to_amount, &amount, cpk);

        assert_eq!(
            bincode::serialize(&new_from_amount).unwrap(),
            bincode::serialize(&new_from_amount_bis).unwrap(),
            "{index}: determinism check failed on transfer from amount",
        );
        assert_eq!(
            bincode::serialize(&new_to_amount).unwrap(),
            bincode::serialize(&new_to_amount_bis).unwrap(),
            "{index}: determinism check failed on transfer to amount",
        );
    }

    // Results are stored back compressed.
    let compressed_outputs = CompressedCiphertextListBuilder::new()
        .push(new_from_amount)
        .push(new_to_amount)
        .build()
        .unwrap();

    let new_from_amount: FheUint64 = compressed_outputs.get(0).unwrap().unwrap();
    let new_to_amount: FheUint64 = compressed_outputs.get(1).unwrap().unwrap();

    let decrypted_new_from: u64 = new_from_amount.decrypt(cks);
    let decrypted_new_to: u64 = new_to_amount.decrypt(cks);
    assert_eq!(
        (decrypted_new_from, decrypted_new_to),
        (expected_new_from, expected_new_to),
        "{index}: transfer results changed value through compression/decompression",
    );

    // Before being handed to threshold decryption, the results are noise squashed.
    let ns_new_from = new_from_amount.squash_noise().unwrap();
    let ns_new_to = new_to_amount.squash_noise().unwrap();

    let decrypted_new_from: u64 = ns_new_from.decrypt(cks);
    let decrypted_new_to: u64 = ns_new_to.decrypt(cks);
    assert_eq!(
        (decrypted_new_from, decrypted_new_to),
        (expected_new_from, expected_new_to),
        "{index}: transfer results changed value through noise squashing",
    );

    // The 128 bit ciphertexts are compressed too.
    let compressed_ns_outputs = CompressedSquashedNoiseCiphertextListBuilder::new()
        .push(ns_new_from)
        .push(ns_new_to)
        .build()
        .unwrap();

    let ns_new_from: SquashedNoiseFheUint = compressed_ns_outputs.get(0).unwrap().unwrap();
    let ns_new_to: SquashedNoiseFheUint = compressed_ns_outputs.get(1).unwrap().unwrap();

    let decrypted_new_from: u64 = ns_new_from.decrypt(cks);
    let decrypted_new_to: u64 = ns_new_to.decrypt(cks);

    assert_eq!(
        decrypted_new_from, expected_new_from,
        "{index}: invalid end to end result on from amount, \
         from: {clear_from_amount}, to: {clear_to_amount}, amount: {clear_amount}",
    );
    assert_eq!(
        decrypted_new_to, expected_new_to,
        "{index}: invalid end to end result on to amount, \
         from: {clear_from_amount}, to: {clear_to_amount}, amount: {clear_amount}",
    );
}

/// Generates the keys and draws every transaction of a run.
///
/// The transactions are drawn up front, on this thread, so that a run is reproducible from its
/// seed whatever order they end up being evaluated in.
fn setup(
    meta_params: MetaParameters,
    test_name: &str,
) -> (
    ClientKey,
    CompressedServerKey,
    CompactPublicKey,
    Vec<Transaction>,
    DeterministicSeeder<DefaultRandomGenerator>,
) {
    let seed = get_user_defined_seed().unwrap_or_else(|| {
        let mut seeder = crate::core_crypto::prelude::new_seeder();
        seeder.seed()
    });
    println!("{test_name}::seed = {}", seed.0);
    println!(
        "{test_name}: replay with TFHE_RS_LONGRUN_TESTS_SEED={}",
        seed.0
    );

    // Everything a run consumes hangs off this one seed: the keys, the encryption noise, the
    // transactions, and the seeds the concurrent workers install on their own threads.
    let mut root = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);
    let key_seed = root.seed();
    let encryption_seed = root.seed();
    let data_seed = root.seed();

    let config = Config::from(meta_params);

    // `generate_with_seed` restores the previous engine when it returns, so the engine is seeded
    // afterwards to cover the server key, the compact public key and every later encryption.
    let cks = ClientKey::generate_with_seed(config, key_seed);
    install_seeded_engine(encryption_seed);

    let compressed_sks = CompressedServerKey::new(&cks);
    let cpk = CompactPublicKey::new(&cks);

    let mut datagen = DeterministicSeeder::<DefaultRandomGenerator>::new(data_seed);
    let transactions = (0..num_transactions())
        .map(|index| Transaction::draw(index, &mut datagen))
        .collect();

    (cks, compressed_sks, cpk, transactions, root)
}

/// One transaction at a time.
fn protocol_transfer_workflow_test(meta_params: MetaParameters) {
    let (cks, compressed_sks, cpk, transactions, _root) =
        setup(meta_params, "protocol_transfer_workflow_test");

    // The transfer graph evaluates its two independent nodes with `rayon::join`, so the workers of
    // the global pool need a server key too. Cloning shares the key material, which sits behind an
    // `Arc`, and hands the worker fresh CUDA streams.
    //
    // This installs a key on the workers of the global rayon pool, so the tests here have to run
    // one at a time, which is what the `test_protocol_*_run_gpu` make targets ask for.
    let gpu_sks = compressed_sks.decompress_to_specific_gpu(GpuIndex::new(TEST_GPU));
    rayon::broadcast(|_| set_server_key(gpu_sks.clone()));
    set_server_key(gpu_sks);

    let num_transactions = transactions.len();
    for (index, transaction) in transactions.iter().enumerate() {
        run_one_transaction(transaction, index, &cks, &cpk);

        if index.is_multiple_of(100) {
            println!("protocol_transfer_workflow_test: {index}/{num_transactions} transactions");
        }
    }
}

/// `NUM_CONCURRENT_TRANSACTIONS` transactions at a time, to put the device under load.
///
/// The transactions are independent, and each one still evaluates its own two independent nodes
/// with `rayon::join`, so the pool is sized to host both levels. Every thread of the pool holds a
/// server key with its own CUDA streams, and work stealing is free to move a node of a transaction
/// onto another thread, hence onto another stream. Losing that alignment is the point: it is what
/// puts the compression, re-randomization and noise squashing stages under concurrent streams.
fn protocol_concurrent_transfer_workflow_test(meta_params: MetaParameters) {
    let (cks, compressed_sks, cpk, transactions, mut root) =
        setup(meta_params, "protocol_concurrent_transfer_workflow_test");

    let gpu_sks = compressed_sks.decompress_to_specific_gpu(GpuIndex::new(TEST_GPU));

    let concurrency = num_concurrent_transactions();
    println!("protocol_concurrent_transfer_workflow_test: {concurrency} transactions in flight");

    // Two threads per in flight transaction: one runs the transaction, the other is there to pick
    // up the second branch of its `rayon::join`.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2 * concurrency)
        // Dropping a pool whose threads hold GPU thread locals needs this, rayon does not wait for
        // thread destruction and the CUDA driver is sensitive to the ordering.
        .exit_handler(|_| clear_gpu_thread_locals())
        .build()
        .unwrap();

    pool.broadcast(|_| set_server_key(gpu_sks.clone()));

    let num_transactions = transactions.len();
    // One chunk per in flight transaction, each chunk is walked sequentially by its worker.
    let chunk_size = num_transactions.div_ceil(concurrency);
    let done = AtomicUsize::new(0);

    // One encryption seed per chunk, drawn here so that a chunk always encrypts the same
    // ciphertexts whichever thread work stealing hands it to.
    let chunk_seeds: Vec<Seed> = (0..num_transactions.div_ceil(chunk_size))
        .map(|_| root.seed())
        .collect();

    pool.install(|| {
        transactions
            .par_chunks(chunk_size)
            .enumerate()
            .for_each(|(chunk_index, chunk)| {
                // The worker running this chunk gets its own seeded engine, so the ciphertexts of
                // the chunk do not depend on which thread picked it up.
                install_seeded_engine(chunk_seeds[chunk_index]);

                for (offset, transaction) in chunk.iter().enumerate() {
                    let index = chunk_index * chunk_size + offset;
                    run_one_transaction(transaction, index, &cks, &cpk);

                    let completed = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if completed.is_multiple_of(100) {
                        println!(
                            "protocol_concurrent_transfer_workflow_test: \
                             {completed}/{num_transactions} transactions",
                        );
                    }
                }
            });
    });
}

// The workflow is checked over both compute atomic patterns, multi bit and classical, and over
// both re-randomization modes:
//
// - a CPK derived from the compute key, no keyswitch, which is what the protocol uses now
// - the legacy dedicated CPK reached through its own keyswitching key
//
// The classical parameter sets carry `CPU` in their name because that is the backend field of the
// meta parameters, but they are run here on the GPU, the same way `xof_key_set::test` exercises
// them.

/// Multi bit compute parameters, re-randomization with a CPK derived from the compute key.
#[test]
fn test_gpu_protocol_erc7984_transfer_workflow_multi_bit() {
    protocol_transfer_workflow_test(
        TEST_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128,
    );
}

/// Multi bit compute parameters, re-randomization through the legacy dedicated CPK and its
/// keyswitching key.
#[test]
fn test_gpu_protocol_erc7984_transfer_workflow_multi_bit_legacy_rerand() {
    protocol_transfer_workflow_test(
        TEST_LEGACY_RERAND_META_PARAM_GPU_2_2_MULTI_BIT_GROUP_4_KS_PBS_PKE_TO_BIG_ZKV2_TUNIFORM_2M128,
    );
}

/// Classical compute parameters, re-randomization with a CPK derived from the compute key.
#[test]
fn test_gpu_protocol_erc7984_transfer_workflow_classical() {
    protocol_transfer_workflow_test(
        TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    );
}

/// Classical compute parameters, re-randomization through the legacy dedicated CPK and its
/// keyswitching key.
#[test]
fn test_gpu_protocol_erc7984_transfer_workflow_classical_legacy_rerand() {
    protocol_transfer_workflow_test(
        TEST_LEGACY_RERAND_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    );
}

/// Several transactions in flight, on the classical compute parameters.
#[test]
fn test_gpu_protocol_erc7984_concurrent_transfer_workflow_classical() {
    protocol_concurrent_transfer_workflow_test(
        TEST_META_PARAM_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    );
}

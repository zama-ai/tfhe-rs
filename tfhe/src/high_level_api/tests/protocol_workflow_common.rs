//! Helpers shared by the protocol workflow tests: the ERC-7984 transfer test and the random
//! operation sequence test both re-randomize every operand of every graph node and both need
//! reproducible, seeded key generation and encryption.

use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::high_level_api::prelude::*;
use crate::integer::server_key::radix_parallel::tests_long_run::{
    get_long_test_iterations, get_user_defined_seed,
};
use crate::shortint::engine::ShortintEngine;
use crate::{
    ClientKey, CompactPublicKey, CompressedServerKey, Config, ReRandomizationContext,
    ReRandomizationSeedGen,
};
use tfhe_csprng::generators::DefaultRandomGenerator;
use tfhe_csprng::seeders::Seed;

/// Domain separator fed to the re-randomization seed generator.
pub(crate) const RERAND_DOMAIN_SEPARATOR: [u8; 8] = *b"TFHE_Rrd";
/// Domain separator used to generate the compact public key encryptions of zero.
pub(crate) const CPK_ENCRYPTION_DOMAIN_SEPARATOR: [u8; 8] = *b"TFHE_Enc";
/// Size of the metadata attached to an input ciphertext, simulating the 256 bits hash that ties
/// an input to its origin.
pub(crate) const METADATA_LEN: usize = 256 / 8;

/// The root seed of a run: `TFHE_RS_LONGRUN_TESTS_SEED` when set, a fresh one otherwise. It is
/// printed with the variable that replays the whole run, since everything the run consumes is
/// derived from it.
pub(crate) fn run_seed(test_name: &str) -> Seed {
    let seed =
        get_user_defined_seed().unwrap_or_else(|| crate::core_crypto::prelude::new_seeder().seed());
    println!("{test_name}::seed = {}", seed.0);
    println!(
        "{test_name}: replay the whole run with TFHE_RS_LONGRUN_TESTS_SEED={}",
        seed.0
    );
    seed
}

/// How many transactions a test runs.
///
/// Defaults to the shared long run count, which the `TFHE_RS_TEST_LONG_TESTS_MINIMAL` environment
/// variable already shortens. The dedicated stress targets override it to size a run to a wall
/// clock budget of their own.
pub(crate) fn num_transactions() -> usize {
    requested_transactions().unwrap_or_else(get_long_test_iterations)
}

/// A positive count read from the environment variable `name`. Zero, an empty value or anything
/// that does not parse counts as unset, for every variable the protocol tests read.
pub(crate) fn positive_env_var<T: std::str::FromStr + Default + PartialEq>(
    name: &str,
) -> Option<T> {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<T>().ok())
        .filter(|v| *v != T::default())
}

/// The transaction count `TFHE_RS_PROTOCOL_TRANSACTIONS` asks for, if any.
pub(crate) fn requested_transactions() -> Option<usize> {
    positive_env_var("TFHE_RS_PROTOCOL_TRANSACTIONS")
}

/// Wall clock budget of a run. When set, it replaces the transaction count: the run keeps drawing
/// new transactions until the budget is spent, which is how the 24 hours soak runs are sized.
pub(crate) fn run_duration() -> Option<std::time::Duration> {
    positive_env_var("TFHE_RS_PROTOCOL_DURATION_SECS").map(std::time::Duration::from_secs)
}

/// Opens the re-randomization context of a single graph node.
///
/// The seeds of a node only depend on the node opcode and on the node operands, so two
/// coprocessors evaluating the same node of the same transaction derive the same seeds.
pub(crate) fn node_re_randomization_context(opcode: u32) -> ReRandomizationContext {
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
pub(crate) fn install_seeded_engine(seed: Seed) {
    let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);
    let engine = ShortintEngine::new_from_seeder(&mut seeder);
    ShortintEngine::with_thread_local_mut(|local_engine| {
        let _ = std::mem::replace(local_engine, engine);
    });
}

/// Draws `N` deterministic bytes, used for the input metadata.
pub(crate) fn random_bytes<const N: usize>(
    datagen: &mut RandomGenerator<DefaultRandomGenerator>,
) -> [u8; N] {
    let mut out = [0u8; N];
    datagen.fill_slice_with_random_uniform(&mut out);
    out
}

/// Re-randomizes one operand of a graph node, with its own seed taken from the node seed stream.
pub(crate) fn re_randomize_operand<T: ReRandomize>(
    ct: &mut T,
    cpk: &CompactPublicKey,
    seed_gen: &mut ReRandomizationSeedGen,
) {
    // Handing over the compact public key covers both re-randomization modes: a server key built
    // on the legacy dedicated CPK uses it along its keyswitching key, a server key holding a CPK
    // derived from the compute key ignores it in favor of the derived one.
    ct.re_randomize(cpk, seed_gen.next_seed().unwrap()).unwrap();
}

/// The key material of a protocol run, every piece derived from the two seeds handed in.
pub(crate) struct ProtocolKeys {
    pub(crate) cks: ClientKey,
    pub(crate) compressed_sks: CompressedServerKey,
    pub(crate) cpk: CompactPublicKey,
}

/// Generates the protocol keys from two seeds, so that a failure report carrying those seeds
/// rebuilds the exact same keys.
///
/// `generate_with_seed` restores the previous engine when it returns, so the engine is seeded
/// afterwards with `setup_seed` to cover the server key and the compact public key. Encryptions
/// draw from whatever engine is installed when they happen: callers seed one per transaction.
pub(crate) fn generate_protocol_keys(
    config: Config,
    key_seed: Seed,
    setup_seed: Seed,
) -> ProtocolKeys {
    let cks = ClientKey::generate_with_seed(config, key_seed);
    install_seeded_engine(setup_seed);

    let compressed_sks = CompressedServerKey::new(&cks);
    let cpk = CompactPublicKey::new(&cks);

    ProtocolKeys {
        cks,
        compressed_sks,
        cpk,
    }
}

/// The GPU side shared by the protocol tests: which device they run on, and how a server key is
/// installed for one transaction at a time or for several in flight.
#[cfg(feature = "gpu")]
pub(crate) mod gpu {
    use crate::{clear_gpu_thread_locals, set_server_key, CompressedServerKey, GpuIndex};

    /// The GPU every test runs on.
    ///
    /// Pinned to a single device on purpose: `decompress_to_gpu` would spread the server key over
    /// every visible GPU, which would make the run time and the memory profile depend on the
    /// machine that picked up the job. On a multi GPU runner the other devices are left idle.
    pub(crate) const TEST_GPU: u32 = 0;

    /// How many transactions a concurrent test keeps in flight:
    /// `TFHE_RS_PROTOCOL_CONCURRENT_TRANSACTIONS` when set to a positive count, to tune the load
    /// to the device at hand, the test's own default otherwise.
    pub(crate) fn num_concurrent_transactions(default: usize) -> usize {
        super::positive_env_var("TFHE_RS_PROTOCOL_CONCURRENT_TRANSACTIONS").unwrap_or(default)
    }

    /// Decompresses the server key to the test GPU and installs it on this thread and on the
    /// workers of the global rayon pool, which operations are free to spill onto. Cloning shares
    /// the key material, which sits behind an `Arc`, and hands each worker fresh CUDA streams.
    ///
    /// This installs a key on the workers of the global rayon pool, so the tests using it have to
    /// run one at a time, which is what their make targets ask for.
    pub(crate) fn install_server_key(compressed_sks: &CompressedServerKey) {
        let gpu_sks = compressed_sks.decompress_to_specific_gpu(GpuIndex::new(TEST_GPU));
        rayon::broadcast(|_| set_server_key(gpu_sks.clone()));
        set_server_key(gpu_sks);
    }

    /// A dedicated pool for `concurrency` transactions in flight, every thread holding the server
    /// key with its own CUDA streams. Two threads per transaction: the headroom hosts whatever
    /// inner parallelism a transaction spawns.
    pub(crate) fn transaction_pool(
        concurrency: usize,
        compressed_sks: &CompressedServerKey,
    ) -> rayon::ThreadPool {
        let gpu_sks = compressed_sks.decompress_to_specific_gpu(GpuIndex::new(TEST_GPU));
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2 * concurrency)
            // Dropping a pool whose threads hold GPU thread locals needs this, rayon does not wait
            // for thread destruction and the CUDA driver is sensitive to the ordering.
            .exit_handler(|_| clear_gpu_thread_locals())
            .build()
            .unwrap();
        pool.broadcast(|_| set_server_key(gpu_sks.clone()));
        pool
    }
}

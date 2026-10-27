//! Helpers shared by the protocol workflow tests: the ERC-7984 transfer test and the random
//! operation sequence test both re-randomize every operand of every graph node and both need
//! reproducible, seeded key generation and encryption.

use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::high_level_api::prelude::*;
use crate::integer::server_key::radix_parallel::tests_long_run::get_long_test_iterations;
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

/// How many transactions a test runs.
///
/// Defaults to the shared long run count, which the `TFHE_RS_TEST_LONG_TESTS_MINIMAL` environment
/// variable already shortens. The dedicated stress targets override it to size a run to a wall
/// clock budget of their own.
pub(crate) fn num_transactions() -> usize {
    std::env::var("TFHE_RS_PROTOCOL_TRANSACTIONS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or_else(get_long_test_iterations)
}

/// Wall clock budget of a run. When set, it replaces the transaction count: the run keeps drawing
/// new transactions until the budget is spent, which is how the 24 hours soak runs are sized.
pub(crate) fn run_duration() -> Option<std::time::Duration> {
    std::env::var("TFHE_RS_PROTOCOL_DURATION_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .map(std::time::Duration::from_secs)
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

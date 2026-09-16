//! Declarative harness for the 'default' radix operation tests.
//!
//! Backends are abstracted with the [`ExecuteOn`] trait.
//! With [`TestBuilder`], a test declares a recipe: the block counts to cover, the number of
//! random cases to draw and the fixed cases to run.
//!
//! The harness will then coordinate test execution: generate inputs, encrypt, execute,
//! check results.
//!
//! The system relies on a few traits [`TestClearInput`], [`TestInput`], [`TestOutput`]
//! which compose nicely on tuples.
use super::tests_cases_unsigned::FunctionExecutor;
use super::tests_unsigned::{blocks_not_clean_or_trivial, MAX_NB_CTXT};
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::tests::uint::Uint;
use crate::integer::{BooleanBlock, ClientKey, IntegerKeyKind, RadixCiphertext, ServerKey};
use crate::shortint::ciphertext::{Degree, MaxDegree};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::*;
use crate::shortint::Ciphertext;
use itertools::iproduct;
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use std::sync::Arc;
use strum::IntoEnumIterator;
use tfhe_csprng::generators::DefaultRandomGenerator;

/// Widest radix the harness can test: clear models are backed by `u128`.
pub(crate) const MAX_RADIX_BITS: u32 = 128;

/// Default block counts depending on parameters
///
/// 2_2 is more extensive than others as its the parameters we rely on
pub(crate) fn default_block_counts(params: TestParameters) -> Vec<u32> {
    let bits_per_block = params.message_modulus().0.ilog2();
    match bits_per_block {
        2 => (1..=32).collect(),
        _ => (1..=MAX_NB_CTXT as u32).collect(),
    }
}

/// Environment variable overriding the seed used by [`TestBuilder`]
/// (decimal or `0x`-prefixed hex).
/// The seed is printed by every run so a failure can be reproduced by
/// setting this variable.
const SEED_ENV_VAR: &str = "TFHE_RADIX_TEST_SEED";

fn parse_seed(s: &str) -> Option<u128> {
    s.strip_prefix("0x")
        .map_or_else(|| s.parse().ok(), |hex| u128::from_str_radix(hex, 16).ok())
}

fn seed_from_env_or_random() -> u128 {
    std::env::var(SEED_ENV_VAR).map_or_else(
        |_| rand::thread_rng().gen(),
        |s| {
            parse_seed(&s)
                .unwrap_or_else(|| panic!("{SEED_ENV_VAR}={s:?} is not a valid u128 seed"))
        },
    )
}

/// Installs a [`ShortintEngine`] on the current thread for the lifetime of the guard, so
/// that key generation and every encryption done on this thread use the test seed.
///
/// The previous engine is restored on drop: `cargo test` reuses threads across tests, and a
/// seeded engine must not leak into whatever runs next on this thread.
struct SeededEngineGuard {
    previous: Option<ShortintEngine>,
}

impl SeededEngineGuard {
    fn install(engine: ShortintEngine) -> Self {
        let previous =
            ShortintEngine::with_thread_local_mut(|local| std::mem::replace(local, engine));
        Self {
            previous: Some(previous),
        }
    }

    /// Swaps the installed engine; the engine a guard restores on drop is the one saved by
    /// [`Self::install`], not this one.
    fn replace(engine: ShortintEngine) {
        ShortintEngine::with_thread_local_mut(|local| *local = engine);
    }
}

impl Drop for SeededEngineGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            ShortintEngine::with_thread_local_mut(|local| *local = previous);
        }
    }
}

/// Things shared by every case of a test run.
///
/// Everything but the keys derives from a single seed:
/// * The encryptions (through a seeded [`ShortintEngine`] installed on the test thread)
/// * The clear values, input states and dirtying amounts (through `rng`).
///
/// Keys come from the key cache, so a run reproduces exactly on the machine that produced
/// the seed, and up to the keys elsewhere. With an empty cache the keys are generated from
/// the seed too.
pub(crate) struct TestContext {
    params: TestParameters,
    /// Used for encrypting and decrypting every ciphertext flowing through the tests
    cks: ClientKey,
    /// The CPU server key, used by the harness to prepare inputs (carries, noise) and handed
    /// to CPU executors (see [`Self::server_key`]).
    sks: Arc<ServerKey>,
    seed: u128,
    _engine_guard: SeededEngineGuard,
}

impl TestContext {
    /// Context seeded from [`SEED_ENV_VAR`] when set, randomly otherwise.
    pub(crate) fn from_env(params: impl Into<TestParameters>) -> Self {
        Self::new(params.into(), seed_from_env_or_random())
    }

    pub(crate) fn new(params: TestParameters, seed: u128) -> Self {
        println!("{SEED_ENV_VAR}={seed:#x}");

        let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(crate::Seed(seed));

        // Keys come from the key cache; on a cache miss they are generated through the
        // thread local engine, i.e. from the seed
        let engine_guard = SeededEngineGuard::install(ShortintEngine::new_from_seeder(&mut seeder));
        let (cks, mut sks) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);
        // The harness checks operations are deterministic
        sks.set_deterministic_pbs_execution(true);

        // Encryptions use a fresh engine from the same seeder, so the noise drawn by the run
        // does not depend on whether the keys were generated or loaded from the cache
        SeededEngineGuard::replace(ShortintEngine::new_from_seeder(&mut seeder));

        Self {
            params,
            cks,
            sks: Arc::new(sks),
            seed,
            _engine_guard: engine_guard,
        }
    }

    /// The server key CPU executors set themselves up with (deterministic PBS enabled).
    pub(crate) fn server_key(&self) -> Arc<ServerKey> {
        self.sks.clone()
    }

    /// The rng for clear values, input states and dirtying amounts, derived from the seed.
    /// Meant to be called once per run.
    pub(crate) fn new_rng(&self) -> StdRng {
        let mut rng_seed = [0u8; 32];
        rng_seed[..16].copy_from_slice(&self.seed.to_le_bytes());
        rng_seed[16..].copy_from_slice(&self.seed.to_be_bytes());
        StdRng::from_seed(rng_seed)
    }

    pub(crate) fn num_blocks_for_bits(&self, bits: u32) -> u32 {
        assert!(bits.is_multiple_of(self.bits_per_block()));
        bits / self.bits_per_block()
    }

    /// Width in bits of a radix of `n_blocks` blocks.
    ///
    /// Clear models are backed by `u128`, so we must ensure we do not have a block count that
    /// would exceed 128 bits total.
    pub(crate) fn radix_bits(&self, n_blocks: u32) -> u32 {
        let bits = n_blocks * self.bits_per_block();
        assert!(
            bits <= MAX_RADIX_BITS,
            "{n_blocks} blocks of {} bits is {bits} bits, the harness supports at most \
             {MAX_RADIX_BITS} bits (clear models are u128)",
            self.bits_per_block()
        );
        bits
    }

    pub(crate) fn bits_per_block(&self) -> u32 {
        self.params.message_modulus().0.ilog2()
    }
}

/// Recipe for a default-op test: which block counts to cover, how many random cases to
/// draw, and hardcoded edge cases.
///
/// `ClearInput` is the tuple of clear inputs of the operation (e.g. `(Uint, Uint)`)
/// It is inferred from the closures given to [`Self::fixed_cases`] and [`Self::execute`].
pub(crate) struct TestBuilder<'a, ClearInput> {
    ctx: &'a TestContext,
    block_counts: Vec<u32>,
    n_random: u32,
    /// Hardcoded cases, built per width in bits since edge values depend on it.
    fixed_cases: Vec<Box<dyn Fn(u32) -> Vec<ClearInput>>>,
}

impl<'a, ClearInput> TestBuilder<'a, ClearInput>
where
    ClearInput: TestClearInput,
    ClearInput::Input: TestInput<Clear = ClearInput>,
{
    pub(crate) fn new(ctx: &'a TestContext) -> Self {
        Self {
            ctx,
            block_counts: default_block_counts(ctx.params),
            n_random: 0,
            fixed_cases: vec![],
        }
    }

    /// Number of random cases per block count (run with clean inputs).
    pub(crate) fn n_random(&mut self, n: u32) -> &mut Self {
        self.n_random = n;
        self
    }

    /// Adds hardcoded cases; `f` receives the width in bits of the radix and returns
    /// the clear inputs to test at that width. Can be called several times.
    pub(crate) fn fixed_cases(
        &mut self,
        f: impl Fn(u32) -> Vec<ClearInput> + 'static,
    ) -> &mut Self {
        self.fixed_cases.push(Box::new(f));
        self
    }

    fn fixed_cases_for_bits(&self, bits: u32) -> Vec<ClearInput> {
        self.fixed_cases.iter().flat_map(|f| f(bits)).collect()
    }

    /// Runs every case with `executor` and panics with the report if any failed.
    ///
    /// For each configured block counts this will run random tests,
    /// fixed tests cases and run the function using combinations of different input state
    /// (see [`InputState`]).
    ///
    /// Execution also checks for determinism, so backends must setup
    /// themselves to execute deterministically
    ///
    /// Failures are collected and printed (panic occurs at the end if there's at least one failure)
    pub(crate) fn execute<Executor, ClearF, Output>(&self, executor: Executor, clear_func: ClearF)
    where
        Executor: ExecuteOn<ClearInput::Input, Output>,
        ClearF: Fn(ClearInput) -> Output::Clear,
        Output: TestOutput,
    {
        let ctx = self.ctx;
        let mut rng = ctx.new_rng();
        let mut runner = CaseRunner::new(ctx, executor, clear_func);

        for n_blocks in self.block_counts.iter().copied() {
            let fixed_cases = self.fixed_cases_for_bits(ctx.radix_bits(n_blocks));

            // Fixed cases and random cases with clean inputs
            let randoms: Vec<ClearInput> = (0..self.n_random)
                .map(|_| ClearInput::generate_random(&mut rng, n_blocks, ctx))
                .collect();
            for clear_inputs in fixed_cases.iter().copied().chain(randoms) {
                runner.run(
                    n_blocks,
                    clear_inputs,
                    <ClearInput::Input as TestInput>::State::clean(),
                    &mut rng,
                );
            }

            // Every combination of input states, to exercise the guards. Non clean inputs
            // are the edge case (the HLAPI serves clean ciphertexts), so one random case per
            // combination is enough; fixed cases only run with clean inputs.
            for states in <ClearInput::Input as TestInput>::State::all_combinations() {
                let clear_inputs = ClearInput::generate_random(&mut rng, n_blocks, ctx);
                runner.run(n_blocks, clear_inputs, states, &mut rng);
            }
        }

        runner.finish();
    }
}

/// Runs cases of one test and collects their failures.
struct CaseRunner<'a, E, ClearF> {
    ctx: &'a TestContext,
    executor: E,
    clear_func: ClearF,
    report: Report,
}

impl<'a, E, ClearF> CaseRunner<'a, E, ClearF> {
    fn new(ctx: &'a TestContext, executor: E, clear_func: ClearF) -> Self {
        Self {
            ctx,
            executor,
            clear_func,
            report: Report::new(ctx.seed),
        }
    }

    /// Prepares the inputs in the given states, runs the operation, validates the result
    /// against the clear model and records any failure.
    ///
    /// With clean inputs the operation is run twice to check it is deterministic.
    /// Non clean inputs are an edge case and the check would double their cost for little value.
    fn run<C, O>(
        &mut self,
        n_blocks: u32,
        clear_inputs: C,
        states: <C::Input as TestInput>::State,
        rng: &mut StdRng,
    ) where
        C: TestClearInput,
        C::Input: TestInput<Clear = C>,
        E: ExecuteOn<C::Input, O>,
        ClearF: Fn(C) -> O::Clear,
        O: TestOutput,
    {
        let (encrypted_inputs, clear_inputs) =
            C::Input::prepare(clear_inputs, states, rng, self.ctx);

        let outputs = self.executor.execute_on(&encrypted_inputs);

        let mut failures = FailureSink::default();
        if states == <C::Input as TestInput>::State::clean()
            && self.executor.execute_on(&encrypted_inputs) != outputs
        {
            failures.push(FailureKind::NonDeterministic);
        }
        outputs.validate((self.clear_func)(clear_inputs), self.ctx, &mut failures);

        self.report.cases_run += 1;
        if !failures.is_empty() {
            self.report.failing_cases.push(CaseFailure {
                n_blocks,
                states: format!("{states:?}"),
                inputs: format!("{clear_inputs:?}"),
                failures: failures.failures,
            });
        }
    }

    /// Panics with the report if any case failed.
    fn finish(self) {
        assert!(self.report.is_empty(), "{}", self.report);
    }
}

/// Why one output of a case did not match its expectation.
#[derive(Debug, strum::EnumIter)]
pub(crate) enum FailureKind {
    /// Decryption succeeded but the value differs from the clear model.
    ValueMismatch { expected: String, got: String },
    /// The radix does not have the block count implied by the clear model's width.
    BlockCountMismatch { expected: u32, got: u32 },
    /// A block of the result is neither trivial nor clean.
    NotClean { block: usize, reason: String },
    /// Executing the operation twice on the same inputs gave different results.
    /// In the bitwise equality sense, not decrypted result sense.
    NonDeterministic,
}

impl FailureKind {
    fn label(&self) -> &'static str {
        match self {
            Self::ValueMismatch { .. } => "value mismatch",
            Self::BlockCountMismatch { .. } => "block count mismatch",
            Self::NotClean { .. } => "result not clean",
            Self::NonDeterministic => "non deterministic",
        }
    }
}

impl std::fmt::Display for FailureKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ValueMismatch { expected, got } => {
                write!(f, "value mismatch: expected {expected}, got {got}")
            }
            Self::BlockCountMismatch { expected, got } => {
                write!(f, "block count mismatch: expected {expected}, got {got}")
            }
            Self::NotClean { block, reason } => write!(f, "block {block} not clean: {reason}"),
            Self::NonDeterministic => write!(f, "two executions gave different results"),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Failure {
    /// Position of the output in the operation's result tuple (0 for a single output).
    output_index: usize,
    kind: FailureKind,
}

/// Sink given to [`TestOutput::validate`]
///
/// Associates each failure with the index of the output being validated.
#[derive(Default)]
pub(crate) struct FailureSink {
    output_index: usize,
    failures: Vec<Failure>,
}

impl FailureSink {
    pub(crate) fn push(&mut self, kind: FailureKind) {
        self.failures.push(Failure {
            output_index: self.output_index,
            kind,
        });
    }

    pub(crate) fn value_mismatch(
        &mut self,
        expected: impl std::fmt::Debug,
        got: impl std::fmt::Debug,
    ) {
        self.push(FailureKind::ValueMismatch {
            expected: format!("{expected:?}"),
            got: format!("{got:?}"),
        });
    }

    /// Moves on to the next output of a multi-output operation.
    fn next_output(&mut self) {
        self.output_index += 1;
    }

    fn is_empty(&self) -> bool {
        self.failures.is_empty()
    }
}

/// One failing case: what was run and everything that went wrong with its outputs.
pub(crate) struct CaseFailure {
    n_blocks: u32,
    /// `Debug` of the input states tuple
    states: String,
    /// `Debug` of the clear inputs, as seen by the clear model (i.e. after `prepare`)
    inputs: String,
    failures: Vec<Failure>,
}

/// Failures of a whole run, printed once at the end.
///
/// Failing cases are collected instead of panicking on the first one, so that one run shows
/// the whole picture (e.g. "every case with a scalar out of the radix range fails", or
/// "only odd block counts fail").
pub(crate) struct Report {
    seed: u128,
    cases_run: usize,
    failing_cases: Vec<CaseFailure>,
}

impl Report {
    fn new(seed: u128) -> Self {
        Self {
            seed,
            cases_run: 0,
            failing_cases: vec![],
        }
    }

    fn is_empty(&self) -> bool {
        self.failing_cases.is_empty()
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{} failing case(s) out of {} run, reproduce with {SEED_ENV_VAR}={:#x}",
            self.failing_cases.len(),
            self.cases_run,
            self.seed
        )?;

        // Summary by kind, in the enum's declaration order
        for kind in FailureKind::iter() {
            let count = self
                .failing_cases
                .iter()
                .flat_map(|case| case.failures.iter())
                .filter(|failure| {
                    std::mem::discriminant(&failure.kind) == std::mem::discriminant(&kind)
                })
                .count();
            if count > 0 {
                writeln!(f, "  {count} x {}", kind.label())?;
            }
        }

        for case in &self.failing_cases {
            writeln!(
                f,
                "\n{} block(s), states {}, inputs {}:",
                case.n_blocks, case.states, case.inputs
            )?;
            for failure in &case.failures {
                writeln!(f, "  output {}: {}", failure.output_index, failure.kind)?;
            }
        }
        Ok(())
    }
}

/// Trait to handle genericity over possible states an input ciphertext may have
/// since ciphertext in radix world have a [`NoiseLevel`] and [`Degree`]
pub(crate) trait InputState: Copy + PartialEq + std::fmt::Debug {
    /// Returns the state representing clean inputs
    fn clean() -> Self;

    /// Every state the harness should exercise for this operand kind.
    ///
    /// For tuples, this is the cartesian product of each element's states.
    fn all_combinations() -> Vec<Self>;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, strum::EnumIter)]
pub(crate) enum RadixState {
    /// Carries empty, nominal noise level: what a fresh encryption or a default operation
    /// gives, and what the HLAPI serves.
    Clean,
    /// Carries empty, every block at the maximum noise level.
    ///
    /// Worst case for noise, but no carries, which has more chance so slip by checks
    /// and trigger noise asserts in tests, pfail lowering in real code
    FullNoise,
    /// Every block at the maximum degree and the maximum noise level: the worst input the
    /// operation is expected to accept.
    Saturated,
}

impl InputState for RadixState {
    fn clean() -> Self {
        Self::Clean
    }

    fn all_combinations() -> Vec<Self> {
        Self::iter().collect()
    }
}

impl InputState for () {
    fn clean() -> Self {}

    fn all_combinations() -> Vec<Self> {
        vec![()]
    }
}

/// Implements the [`InputState`] trait for tuples, this is how we handle
/// different arity (unary, binary)
macro_rules! impl_input_state_for_tuple {
    // `iproduct!` with a single iterator yields the elements themselves, not 1-tuples.
    ($ty:ident) => {
        impl<$ty> InputState for ($ty,)
        where
            $ty: InputState,
        {
            fn clean() -> Self {
                ($ty::clean(),)
            }

            fn all_combinations() -> Vec<Self> {
                $ty::all_combinations().into_iter().map(|a| (a,)).collect()
            }
        }
    };
    ($($ty:ident),+) => {
        impl<$($ty),+> InputState for ($($ty,)+)
        where
            $($ty: InputState,)+
        {
            fn clean() -> Self {
                ($($ty::clean(),)+)
            }

            fn all_combinations() -> Vec<Self> {
                iproduct!($($ty::all_combinations()),+).collect()
            }
        }
    };
}

impl_input_state_for_tuple!(A);
impl_input_state_for_tuple!(A, B);

/// Trait for types representing clear inputs of a test
pub(crate) trait TestClearInput: Copy + std::fmt::Debug {
    /// The input type that this clear input maps to once prepared
    ///
    /// As radix integer operations have variants accepting clear(s), an input
    /// type is not necessarily an encrypted type.
    ///
    /// The harness derives the signature of the FHE function based on this
    type Input;

    /// Draws a random clear value fitting in `n_blocks` radix blocks under `ctx`'s parameters.
    fn generate_random(rng: &mut dyn RngCore, n_blocks: u32, ctx: &TestContext) -> Self;
}

/// Trait for inputs of an FHE function to be tested.
///
/// Since FHE functions have variant accepting clears (e.g. scalar_add),
/// this trait is not reserved for encrypted types.
pub(crate) trait TestInput: Sized {
    /// The clear this input is mapped from
    type Clear;

    /// The reference type of self (Copy types may return copies and not refs)
    ///
    /// Allows the [`ExecuteOn`] trait to simply bridge to the [`FunctionExecutor`]
    type Ref<'a>
    where
        Self: 'a;

    /// The possible states
    type State: InputState;

    /// Builds the operand from its clear value, in the requested state.
    ///
    /// Returns the clear value the operand actually holds afterwards
    /// as the requested state might mean the actual encrypted value is different.
    /// For example, putting carries in a radix changes the encrypted value.
    fn prepare(
        clear: Self::Clear,
        state: Self::State,
        rng: &mut dyn RngCore,
        ctx: &TestContext,
    ) -> (Self, Self::Clear);

    fn as_ref(&self) -> Self::Ref<'_>;
}

/// Brings every block to the maximum noise level without changing its value or degree.
///
/// Noise is added for real, by adding fresh encryptions of zero.
fn saturate_noise(
    cks: &crate::shortint::ClientKey,
    sks: &crate::shortint::ServerKey,
    blocks: &mut [Ciphertext],
) {
    let max_noise_level = cks.parameters().max_noise_level();
    let mut zero_block = cks.encrypt(0);
    zero_block.degree = Degree::new(0);
    for block in blocks {
        while block.noise_level().get() < max_noise_level.get() {
            sks.unchecked_add_assign(block, &zero_block);
        }
        assert_eq!(block.noise_level().get(), max_noise_level.get());
    }
}

/// Brings every block to the maximum degree, without adding noise
///
/// Returns the clear the radix encrypts after the modifications done
fn saturate_degree(
    cks: &crate::shortint::ClientKey,
    sks: &crate::shortint::ServerKey,
    clear: Uint,
    blocks: &mut [Ciphertext],
) -> Uint {
    let max_degree = MaxDegree::from_msg_carry_modulus(
        cks.parameters().message_modulus(),
        cks.parameters().carry_modulus(),
    )
    .get();

    let mut current_clear = clear;
    let msg_mod = u128::from(cks.parameters().message_modulus().0);
    for (i, block) in blocks.iter_mut().enumerate() {
        let amount = max_degree
            .checked_sub(block.degree.get())
            .expect("Degree greater than max degree");
        // should never happen
        let amount_u8: u8 = amount.try_into().expect("Value exceeds u8");
        sks.unchecked_scalar_add_assign(block, amount_u8);
        assert_eq!(block.degree.get(), max_degree);

        let added = Uint::new(
            current_clear.bits(),
            u128::from(amount).wrapping_mul(msg_mod.checked_pow(i as u32).unwrap()),
        );
        current_clear = current_clear.wrapping_add(added);
    }

    current_clear
}

impl TestClearInput for Uint {
    type Input = RadixCiphertext;

    fn generate_random(rng: &mut dyn RngCore, n_blocks: u32, ctx: &TestContext) -> Self {
        // The Uint stores the number of bits, this is what the radix will use to create
        // its proper size
        Self::random(ctx.radix_bits(n_blocks))(rng)
    }
}

impl TestInput for RadixCiphertext {
    type Clear = Uint;

    type Ref<'a> = &'a Self;

    type State = RadixState;

    fn prepare(
        mut clear: Self::Clear,
        state: Self::State,
        _rng: &mut dyn RngCore,
        ctx: &TestContext,
    ) -> (Self, Self::Clear) {
        let n_blocks = ctx.num_blocks_for_bits(clear.bits()) as usize;
        let mut encrypted = ctx.cks.encrypt_radix(clear.value(), n_blocks);

        match state {
            RadixState::Clean => {}
            RadixState::FullNoise => {
                saturate_noise(&ctx.cks.key, &ctx.sks.key, &mut encrypted.blocks);
                assert!(encrypted.block_carries_are_empty());
            }
            RadixState::Saturated => {
                saturate_noise(&ctx.cks.key, &ctx.sks.key, &mut encrypted.blocks);
                clear = saturate_degree(&ctx.cks.key, &ctx.sks.key, clear, &mut encrypted.blocks);
                let dec: u128 = ctx.cks.decrypt_radix(&encrypted);
                assert_eq!(
                    dec,
                    clear.value(),
                    "Test setup failed: radix and clear no longer in sync"
                );
            }
        }

        (encrypted, clear)
    }

    fn as_ref(&self) -> Self::Ref<'_> {
        self
    }
}

/// Rust scalar types accepted by the `scalar_*` operations, as seen by the harness.
pub(crate) trait ScalarType: Copy + std::fmt::Debug + 'static {
    const BITS: u32;
    /// The type's maximum, widened to the clear model's precision.
    const MAX: u128;
    fn from_u128(value: u128) -> Self;
}

macro_rules! impl_scalar_type {
    ($($ty:ty),+) => {
        $(
            impl ScalarType for $ty {
                const BITS: u32 = <$ty>::BITS;
                const MAX: u128 = <$ty>::MAX as u128;

                fn from_u128(value: u128) -> Self {
                    value as $ty
                }
            }
        )+
    };
}

impl_scalar_type!(u8, u16, u32, u64, u128);

/// Wraps a Uint to use T::BITS bits of precision
///
/// The purpose of this is that in radix scalar operations, the scalar is on some type
/// `T` which can allow to represent values bigger that what the radix type used in the same
/// operation could encrypt.
///
/// For example, take a radix of 4 blocks, param 2_2 => radix has 8 bits,
/// We can do a `scalar_add(radix, Xu16);`, the u16 can store a value that exceeds
/// the 8 bits of the radix.
///
/// So in the tests harness, to allow representing these cases we use this wrapper.
/// e.g using `TestScalar<u64>` when building a test for a scalar test, means the value of the
/// random scalar used will be in the range of a u64 (but stored on a Uint)
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) struct TestScalar<T> {
    value: Uint,
    _marker: std::marker::PhantomData<T>,
}

impl<T> std::fmt::Debug for TestScalar<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TestScalar<{}>({})",
            std::any::type_name::<T>(),
            self.value.value()
        )
    }
}

impl<T: ScalarType> TestScalar<T> {
    pub(crate) fn new(value: u128) -> Self {
        Self {
            value: Uint::new(T::BITS, value),
            _marker: std::marker::PhantomData,
        }
    }

    /// The scalar as a `Uint` of `T::BITS` bits, for operations working at full precision
    /// (comparisons).
    pub(crate) fn uint(self) -> Uint {
        self.value
    }

    /// The scalar reduced to `bits` bits, i.e. what operations that truncate the scalar to
    /// the radix width see.
    pub(crate) fn cast(self, bits: u32) -> Uint {
        self.value.cast(bits)
    }

    fn to_scalar(self) -> T {
        T::from_u128(self.value.value())
    }
}

/// Fixed cases for an operation between a radix of `radix_bits` bits and a scalar of type
/// `T`: the radix bounds (zero, one, max) against the scalar edge values (see
/// [`scalar_edge_values`]).
pub(crate) fn default_scalar_fixed_cases<T: ScalarType>(
    radix_bits: u32,
) -> Vec<(Uint, TestScalar<T>)> {
    let radix_edges = [
        Uint::zero(radix_bits),
        Uint::one(radix_bits),
        Uint::max(radix_bits),
    ];
    let scalar_edges = scalar_edge_values::<T>(radix_bits);
    radix_edges
        .into_iter()
        .flat_map(|lhs| scalar_edges.iter().map(move |&rhs| (lhs, rhs)))
        .collect()
}

/// TestScalar values worth testing against a radix of `radix_bits` bits: zero, one, the radix
/// bounds, just past them, and the type maximum.
///
/// "Just past" includes `2 * radix_max + 1`: every radix bit set plus a single excess bit.
/// Implementations decompose the scalar in blocks, and an excess confined to the block
/// holding the radix's top bits, combined with a non zero in-range part, is a known blind
/// spot that `radix_max + 1` alone does not exercise.
fn scalar_edge_values<T: ScalarType>(radix_bits: u32) -> Vec<TestScalar<T>> {
    let type_max = T::MAX;
    let radix_max = Uint::max(radix_bits).value();
    let mut values = vec![0, 1, radix_max, type_max];
    if radix_max < type_max {
        // radix_bits < T::BITS, so the largest of these, 2^(radix_bits + 1) - 1, fits in the
        // type and in u128
        values.extend([radix_max + 1, radix_max + 2, 2 * radix_max + 1]);
    }
    values.sort_unstable();
    values.dedup();
    values.into_iter().map(TestScalar::new).collect()
}

impl<T: ScalarType> TestClearInput for TestScalar<T> {
    type Input = T;

    /// Half of the draws fit in the radix, the other half exceed it (when the type allows).
    ///
    /// To pick values of of the normal range, 2 steps are involved:
    /// 1) Randomly pick a bit length in `radix_bits + 1..=T::BITS` (so a bit length greater than
    ///    the normal bit length)
    /// 2) Pick a random value that is within the [min, max] corresponding to the bit length
    ///
    /// This is done this way do augment the chances of picking values that are
    /// 'just" past the radix size, and not pick always values way beyond the radix range.
    fn generate_random(rng: &mut dyn RngCore, n_blocks: u32, ctx: &TestContext) -> Self {
        let radix_bits = ctx.radix_bits(n_blocks).min(T::BITS);
        let value = if radix_bits < T::BITS && rng.gen_bool(0.5) {
            let bit_length = rng.gen_range(radix_bits + 1..=T::BITS);
            rng.gen_range(1u128 << (bit_length - 1)..=Uint::max(bit_length).value())
        } else {
            rng.gen_range(0..=Uint::max(radix_bits).value())
        };
        Self::new(value)
    }
}

macro_rules! impl_test_input_for_scalar {
    ($($ty:ty),+) => {
        $(
            impl TestInput for $ty {
                type Clear = TestScalar<$ty>;

                type Ref<'a> = $ty;

                // Scalars have no state
                type State = ();

                fn prepare(
                    clear: Self::Clear,
                    _state: (),
                    _rng: &mut dyn RngCore,
                    _ctx: &TestContext,
                ) -> (Self, Self::Clear) {
                    (clear.to_scalar(), clear)
                }

                fn as_ref(&self) -> Self::Ref<'_> {
                    *self
                }
            }
        )+
    };
}

impl_test_input_for_scalar!(u8, u16, u32, u64, u128);

/// Implements the [`TestInput`] trait for tuples, this is how we handle
/// different arity (unary, binary)
macro_rules! impl_test_input_for_tuple {
    ($($ty:ident . $idx:tt),+) => {
        impl<$($ty),+> TestClearInput for ($($ty,)+)
        where
            $($ty: TestClearInput,)+
        {
            type Input = ($($ty::Input,)+);

            fn generate_random(rng: &mut dyn RngCore, n_blocks: u32, ctx: &TestContext) -> Self {
                ($($ty::generate_random(rng, n_blocks, ctx),)+)
            }
        }

        impl<$($ty),+> TestInput for ($($ty,)+)
        where
            $($ty: TestInput,)+
        {
            type Clear = ($($ty::Clear,)+);

            type Ref<'a>
                = ($($ty::Ref<'a>,)+)
            where
                Self: 'a;

            type State = ($($ty::State,)+);

            fn prepare(
                clear: Self::Clear,
                state: Self::State,
                rng: &mut dyn RngCore,
                ctx: &TestContext,
            ) -> (Self, Self::Clear) {
                #[allow(non_snake_case)]
                let ($($ty,)+) = ($($ty::prepare(clear.$idx, state.$idx, rng, ctx),)+);
                (($($ty.0,)+), ($($ty.1,)+))
            }

            fn as_ref(&self) -> Self::Ref<'_> {
                ($(self.$idx.as_ref(),)+)
            }
        }
    };
}

impl_test_input_for_tuple!(A.0);
impl_test_input_for_tuple!(A.0, B.1);

/// Trait for outputs of a FHE function that is tested
///
/// `PartialEq` is required to check the operation is deterministic.
pub(crate) trait TestOutput: PartialEq {
    type Clear;

    /// Checks the output against the clear model, reporting problems into `failures`.
    fn validate(&self, expected: Self::Clear, ctx: &TestContext, failures: &mut FailureSink);
}

impl TestOutput for RadixCiphertext {
    type Clear = Uint;

    fn validate(&self, expected: Self::Clear, ctx: &TestContext, failures: &mut FailureSink) {
        let expected_n_blocks = ctx.num_blocks_for_bits(expected.bits());
        if self.blocks.len() as u32 != expected_n_blocks {
            failures.push(FailureKind::BlockCountMismatch {
                expected: expected_n_blocks,
                got: self.blocks.len() as u32,
            });
        }

        let decrypted: u128 = ctx.cks.decrypt_radix(self);
        if decrypted != expected.value() {
            failures.value_mismatch(expected.value(), decrypted);
        }

        for (block, reason) in blocks_not_clean_or_trivial(self, &ctx.cks) {
            failures.push(FailureKind::NotClean { block, reason });
        }
    }
}

impl TestOutput for BooleanBlock {
    type Clear = bool;

    fn validate(&self, expected: Self::Clear, ctx: &TestContext, failures: &mut FailureSink) {
        let decrypted = ctx.cks.decrypt_bool(self);
        if decrypted != expected {
            failures.value_mismatch(expected, decrypted);
        }

        if self.0.noise_level() > NoiseLevel::NOMINAL {
            failures.push(FailureKind::NotClean {
                block: 0,
                reason: format!("non nominal noise level: {:?}", self.0.noise_level()),
            });
        }

        if self.0.degree.get() > 1 {
            failures.push(FailureKind::NotClean {
                block: 0,
                reason: format!("degree {:?} exceeds 1", self.0.degree),
            });
        }
    }
}

/// Implements the [`TestOutput`] trait for tuples, this is how we handle
/// different number of return values
macro_rules! impl_test_output_for_tuple {
    ($($ty:ident . $idx:tt),+) => {
        impl<$($ty),+> TestOutput for ($($ty,)+)
        where
            $($ty: TestOutput,)+
        {
            type Clear = ($($ty::Clear,)+);

            fn validate(&self, expected: Self::Clear, ctx: &TestContext, failures: &mut FailureSink) {
                $(
                    self.$idx.validate(expected.$idx, ctx, failures);
                    failures.next_output();
                )+
            }
        }
    }
}

impl_test_output_for_tuple!(A.0);
impl_test_output_for_tuple!(A.0, B.1);

/// Bridges the owned inputs built by the harness to the borrowed inputs the
/// [`FunctionExecutor`] impls accept.
///
/// The harness keeps ownership of the inputs so it can run the operation several
/// times (determinism) and decrypt the inputs afterwards.
/// FunctionExecutors receive `(&A, &B, ..)` tuples, or the value itself for scalar operands.
///
/// There is one blanket impl per arity, and inputs are always tuples (one-tuples
/// for unary operations): the tuple shape has to be visible in the
/// `FunctionExecutor` bound, otherwise the trait solver cannot normalize the
/// `TestInput::Ref` projections under the `for<'a>` binder and picks the wrong
/// `CpuFunctionExecutor` impl.
pub(crate) trait ExecuteOn<I: TestInput, O> {
    fn execute_on(&mut self, input: &I) -> O;
}

macro_rules! impl_execute_on_for_tuple {
    ($($ty:ident . $idx:tt),+) => {
        impl<E, O, $($ty),+> ExecuteOn<($($ty,)+), O> for E
        where
            $($ty: TestInput,)+
            E: for<'a> FunctionExecutor<($($ty::Ref<'a>,)+), O>,
        {
            fn execute_on(&mut self, input: &($($ty,)+)) -> O {
                self.execute(($(input.$idx.as_ref(),)+))
            }
        }
    };
}

impl_execute_on_for_tuple!(A.0);
impl_execute_on_for_tuple!(A.0, B.1);

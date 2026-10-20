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
use crate::integer::keycache::KEY_CACHE;
use crate::integer::tests::int::Int;
use crate::integer::tests::uint::Uint;
use crate::integer::{
    BooleanBlock, ClientKey, IntegerKeyKind, RadixCiphertext, ServerKey, SignedRadixCiphertext,
};
use crate::shortint::ciphertext::{Degree, MaxDegree};
use crate::shortint::parameters::*;
use crate::shortint::Ciphertext;
use itertools::iproduct;
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use std::sync::Arc;
use strum::IntoEnumIterator;

/// Widest radix the harness can test: clear models are backed by `u128`.
pub(crate) const MAX_RADIX_BITS: u32 = 128;

/// Highest block count the tests go up to, depending on parameters
///
/// 2_2 is more extensive than others as its the parameters we rely on
pub(crate) fn max_block_requirement(params: TestParameters) -> u32 {
    let bits_per_block = params.message_modulus().0.ilog2();
    match bits_per_block {
        2 => 32,
        _ => MAX_NB_CTXT as u32,
    }
}

/// Default block counts depending on parameters
pub(crate) fn default_block_requirements(params: TestParameters) -> Vec<SizeRequirements> {
    (1..=max_block_requirement(params))
        .map(SizeRequirements::new_scalar)
        .collect()
}

/// Block budget for a vector operation about as costly as a sum.
///
/// Operations doing more work per block need a smaller budget to run in a comparable time,
/// hence [`vec_size_requirements_with_budget`].
pub(crate) const DEFAULT_VEC_BLOCK_BUDGET: u32 = 128;

/// [`vec_size_requirements_with_budget`] with [`DEFAULT_VEC_BLOCK_BUDGET`].
pub(crate) fn vec_size_requirements(
    ctx: &TestContext,
    vec_lens: impl IntoIterator<Item = u32>,
) -> Vec<SizeRequirements> {
    vec_size_requirements_with_budget(ctx, vec_lens, DEFAULT_VEC_BLOCK_BUDGET)
}

/// Block counts to pair with each of `vec_lens`, for a test taking a vector input.
///
/// The cost of a vector operation grows with both the number of elements and the number of
/// blocks of each element, so sweeping the two axes independently is too slow. The block
/// count is instead made to shrink as the vector grows, which keeps the total amount of
/// work per case roughly flat while still reaching both ends of both axes: short vectors
/// are tested with wide radixes, long vectors with narrow ones.
///
/// `budget` is how many blocks a case may use in total, summed over the elements of one
/// input vector. It is only a budget, not a hard limit: an element is never given less
/// than one block, so a vector longer than `budget` goes over it. The right value depends
/// on how costly the tested operation is per block, so each test picks its own, starting
/// from [`DEFAULT_VEC_BLOCK_BUDGET`].
pub(crate) fn vec_size_requirements_with_budget(
    ctx: &TestContext,
    vec_lens: impl IntoIterator<Item = u32>,
    budget: u32,
) -> Vec<SizeRequirements> {
    let max_n_blocks = max_block_requirement(ctx.params);
    vec_lens
        .into_iter()
        .map(|vec_len| SizeRequirements {
            // `max(1)` as the empty vector has no element to size, any block count does
            n_blocks: (budget / vec_len.max(1)).clamp(1, max_n_blocks),
            vec_len: Some(vec_len),
        })
        .collect()
}

/// Environment variable overriding the seed used by [`TestBuilder`]
/// (decimal or `0x`-prefixed hex).
/// The seed is printed by every run so the cases of a failing run (clear values, input
/// states) can be reproduced by setting this variable.
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

/// Environment variable stopping a run at its first failing case, when set to anything but
/// `0` or the empty string.
///
/// By default every case runs and the failures are reported together at the end,
/// which shows the whole picture but makes debugging a single failure slow.
const FAIL_FAST_ENV_VAR: &str = "TFHE_RADIX_TEST_FAIL_FAST";

fn fail_fast_from_env() -> bool {
    std::env::var(FAIL_FAST_ENV_VAR).is_ok_and(|s| !s.is_empty() && s != "0")
}

/// Things shared by every case of a test run.
///
/// The clear values, input states and dirtying amounts derive from a single seed (through
/// the rng), so a seed reproduces the cases of a run. Keys come from the key cache and the
/// encryption noise from the thread local engine, so it does not reproduce the ciphertexts.
pub(crate) struct TestContext {
    params: TestParameters,
    /// Used for encrypting and decrypting every ciphertext flowing through the tests
    cks: ClientKey,
    /// The CPU server key.
    /// The harness prepares inputs with it (carries, noise) and CPU executors run with it
    cpu_sks: Arc<ServerKey>,
    seed: u128,
    /// Stop at the first failing case instead of collecting them all.
    fail_fast: bool,
}

impl TestContext {
    /// Context seeded from [`SEED_ENV_VAR`] when set, randomly otherwise, and failing fast
    /// when [`FAIL_FAST_ENV_VAR`] is set.
    pub(crate) fn from_env(params: impl Into<TestParameters>) -> Self {
        let params = params.into();
        let seed = seed_from_env_or_random();
        println!("{SEED_ENV_VAR}={seed:#x}");

        let (cks, mut sks) = KEY_CACHE.get_from_params(params, IntegerKeyKind::Radix);
        // The harness checks operations are deterministic
        sks.set_deterministic_pbs_execution(true);

        Self {
            params,
            cks,
            cpu_sks: Arc::new(sks),
            seed,
            fail_fast: fail_fast_from_env(),
        }
    }

    /// The server key CPU executors set themselves up with (deterministic PBS enabled).
    pub(crate) fn server_key(&self) -> Arc<ServerKey> {
        self.cpu_sks.clone()
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

/// Required sizes an input of a test must follow when generating the inputs
///
/// `n_blocks` is for radix
/// `vec_len` is for vec
///
/// e.g: a test working with some Vec<RadixCiphertext> as input may see
/// n_blocks = 4, vec_len = 8, it means it MUST produce an input Vec with 8 elements
/// and each of them has 4 blocks
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct SizeRequirements {
    pub(crate) n_blocks: u32,
    pub(crate) vec_len: Option<u32>,
}

impl SizeRequirements {
    /// Creates a requirement that only specifies a number of blocks,
    /// meant for tests on scalar values like `RadixCiphertext`
    pub(crate) fn new_scalar(n_blocks: u32) -> Self {
        Self {
            n_blocks,
            vec_len: None,
        }
    }
}

/// Builder of the hardcoded cases of a test, for one size requirement.
type FixedCaseFn<ClearInput> = Box<dyn Fn(SizeRequirements, &TestContext) -> Vec<ClearInput>>;

/// Recipe for a default-op test: which block counts to cover, how many random cases to
/// draw, and hardcoded edge cases.
///
/// `ClearInput` is the tuple of clear inputs of the operation (e.g. `(Uint, Uint)`)
/// It is inferred from the closures given to [`Self::fixed_cases`] and [`Self::execute`].
pub(crate) struct TestBuilder<'a, ClearInput> {
    ctx: &'a TestContext,
    size_requirements: Vec<SizeRequirements>,
    n_random: u32,
    /// Hardcoded cases, built per size requirement since edge values depend on the radix
    /// width (and, for vector inputs, on the number of elements).
    fixed_cases: Vec<FixedCaseFn<ClearInput>>,
}

impl<'a, ClearInput> TestBuilder<'a, ClearInput>
where
    ClearInput: TestClearInput,
    ClearInput::Input: TestInput<Clear = ClearInput>,
{
    pub(crate) fn new(ctx: &'a TestContext) -> Self {
        Self {
            ctx,
            size_requirements: default_block_requirements(ctx.params),
            n_random: 0,
            fixed_cases: vec![],
        }
    }

    pub(crate) fn size_requirements(
        &mut self,
        size_requirements: Vec<SizeRequirements>,
    ) -> &mut Self {
        self.size_requirements = size_requirements;
        self
    }

    /// Number of random cases per block count (run with clean inputs).
    pub(crate) fn n_random(&mut self, n: u32) -> &mut Self {
        self.n_random = n;
        self
    }

    /// Adds hardcoded cases; `f` receives the size the inputs must satisfy and returns the
    /// clear inputs to test at that size. `ctx` is passed along so `f` can turn a block count
    /// into a width in bits, which is what edge values depend on. Can be called several times.
    pub(crate) fn fixed_cases(
        &mut self,
        f: impl Fn(SizeRequirements, &TestContext) -> Vec<ClearInput> + 'static,
    ) -> &mut Self {
        self.fixed_cases.push(Box::new(f));
        self
    }

    fn fixed_cases_for_requirements(&self, size_requirements: SizeRequirements) -> Vec<ClearInput> {
        self.fixed_cases
            .iter()
            .flat_map(|f| f(size_requirements, self.ctx))
            .collect()
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

        for size_req in self.size_requirements.iter().copied() {
            let fixed_cases = self.fixed_cases_for_requirements(size_req);

            // Fixed cases and random cases with clean inputs
            let randoms: Vec<ClearInput> = (0..self.n_random)
                .map(|_| ClearInput::generate_random(&mut rng, size_req, ctx))
                .collect();
            for clear_inputs in fixed_cases.iter().cloned().chain(randoms) {
                runner.run(
                    size_req,
                    clear_inputs,
                    <ClearInput::Input as TestInput>::State::clean(),
                    &mut rng,
                );
            }

            // Every combination of input states, to exercise the guards. Non clean inputs
            // are the edge case (the HLAPI serves clean ciphertexts), so one random case per
            // combination is enough; fixed cases only run with clean inputs.
            for states in <ClearInput::Input as TestInput>::State::all_combinations() {
                let clear_inputs = ClearInput::generate_random(&mut rng, size_req, ctx);
                runner.run(size_req, clear_inputs, states, &mut rng);
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
        size_req: SizeRequirements,
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

        // A panic is recorded as a failure of the case, so that one run still shows every
        // failing case. The panic hook has already printed the message and the backtrace.
        let executor = &mut self.executor;
        let outputs = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            executor.execute_on(&encrypted_inputs)
        })) {
            Ok(outputs) => outputs,
            Err(payload) => {
                let message = payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
                    .unwrap_or_default();
                let failures = vec![Failure {
                    output_index: 0,
                    kind: FailureKind::Panicked(message),
                }];
                self.record(size_req, &states, &clear_inputs, failures);
                return;
            }
        };

        let mut failures = FailureSink::default();
        if states == <C::Input as TestInput>::State::clean()
            && self.executor.execute_on(&encrypted_inputs) != outputs
        {
            failures.push(FailureKind::NonDeterministic);
        }
        outputs.validate(
            (self.clear_func)(clear_inputs.clone()),
            self.ctx,
            &mut failures,
        );
        self.record(size_req, &states, &clear_inputs, failures.failures);
    }

    /// Counts a case that ran, and adds it to the report if it failed.
    ///
    /// Panics with the report on the first failure when failing fast.
    fn record(
        &mut self,
        size_req: SizeRequirements,
        states: &impl std::fmt::Debug,
        clear_inputs: &impl std::fmt::Debug,
        failures: Vec<Failure>,
    ) {
        self.report.cases_run += 1;
        if failures.is_empty() {
            return;
        }
        self.report.failing_cases.push(CaseFailure {
            size_req,
            states: format!("{states:?}"),
            inputs: format!("{clear_inputs:?}"),
            failures,
        });
        assert!(!self.ctx.fail_fast, "{}", self.report);
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
    /// The operation panicked, the message is the panic payload.
    Panicked(String),
}

impl FailureKind {
    fn label(&self) -> &'static str {
        match self {
            Self::ValueMismatch { .. } => "value mismatch",
            Self::BlockCountMismatch { .. } => "block count mismatch",
            Self::NotClean { .. } => "result not clean",
            Self::NonDeterministic => "non deterministic",
            Self::Panicked(_) => "panicked",
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
            Self::Panicked(message) => write!(f, "panicked: {message}"),
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
}

/// One failing case: what was run and everything that went wrong with its outputs.
pub(crate) struct CaseFailure {
    size_req: SizeRequirements,
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
                "\nsize_requirements {:?}, states {}, inputs {}:",
                case.size_req, case.states, case.inputs
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
impl_input_state_for_tuple!(A, B, C);

/// Trait for types representing clear inputs of a test
pub(crate) trait TestClearInput: Clone + std::fmt::Debug {
    /// The input type that this clear input maps to once prepared
    ///
    /// As radix integer operations have variants accepting clear(s), an input
    /// type is not necessarily an encrypted type.
    ///
    /// The harness derives the signature of the FHE function based on this
    type Input;

    /// Draws a random clear value fitting the requirements
    fn generate_random(
        rng: &mut dyn RngCore,
        size_requirements: SizeRequirements,
        ctx: &TestContext,
    ) -> Self;
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
/// Brings every block to the maximum degree by adding clear amounts to it.
///
/// Returns the total amount added to the radix value on a u128,
/// thus the `blocks` cannot exceed 128 bits of precision.
fn saturate_degree(
    cks: &crate::shortint::ClientKey,
    sks: &crate::shortint::ServerKey,
    blocks: &mut [Ciphertext],
) -> u128 {
    let bits_per_block = cks.parameters().message_modulus().0.ilog2();
    assert!(
        blocks.len() as u32 * bits_per_block <= MAX_RADIX_BITS,
        "{} blocks of {bits_per_block} bits exceed the {MAX_RADIX_BITS} bits of the clear models",
        blocks.len()
    );

    let max_degree = MaxDegree::from_msg_carry_modulus(
        cks.parameters().message_modulus(),
        cks.parameters().carry_modulus(),
    )
    .get();

    let msg_mod = u128::from(cks.parameters().message_modulus().0);
    let mut added = 0u128;
    for (i, block) in blocks.iter_mut().enumerate() {
        let amount = max_degree
            .checked_sub(block.degree.get())
            .expect("Degree greater than max degree");
        // should never happen
        let amount_u8: u8 = amount.try_into().expect("Value exceeds u8");
        sks.unchecked_scalar_add_assign(block, amount_u8);
        assert_eq!(block.degree.get(), max_degree);

        added = added
            .wrapping_add(u128::from(amount).wrapping_mul(msg_mod.checked_pow(i as u32).unwrap()));
    }

    added
}

impl TestClearInput for Uint {
    type Input = RadixCiphertext;

    fn generate_random(
        rng: &mut dyn RngCore,
        size_requirements: SizeRequirements,
        ctx: &TestContext,
    ) -> Self {
        // The Uint stores the number of bits, this is what the radix will use to create
        // its proper size
        Self::random(ctx.radix_bits(size_requirements.n_blocks))(rng)
    }
}

impl TestClearInput for bool {
    type Input = BooleanBlock;

    fn generate_random(
        rng: &mut dyn RngCore,
        _size_requirements: SizeRequirements,
        _ctx: &TestContext,
    ) -> Self {
        rng.gen_bool(0.5)
    }
}

impl TestClearInput for Int {
    type Input = SignedRadixCiphertext;

    fn generate_random(
        rng: &mut dyn RngCore,
        size_requirements: SizeRequirements,
        ctx: &TestContext,
    ) -> Self {
        Self::random(ctx.radix_bits(size_requirements.n_blocks))(rng)
    }
}

impl TestClearInput for Vec<Uint> {
    type Input = Vec<RadixCiphertext>;

    fn generate_random(
        rng: &mut dyn RngCore,
        size_requirements: SizeRequirements,
        ctx: &TestContext,
    ) -> Self {
        (0..size_requirements
            .vec_len
            .expect("vector tests needs SizeRequirements with a vec_len"))
            .map(|_| <Uint as TestClearInput>::generate_random(rng, size_requirements, ctx))
            .collect()
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
                saturate_noise(&ctx.cks.key, &ctx.cpu_sks.key, &mut encrypted.blocks);
                assert!(encrypted.block_carries_are_empty());
            }
            RadixState::Saturated => {
                saturate_noise(&ctx.cks.key, &ctx.cpu_sks.key, &mut encrypted.blocks);
                let added = saturate_degree(&ctx.cks.key, &ctx.cpu_sks.key, &mut encrypted.blocks);
                clear = clear.wrapping_add(Uint::new(added, clear.bits()));
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

impl TestInput for BooleanBlock {
    type Clear = bool;

    type Ref<'a>
        = &'a Self
    where
        Self: 'a;

    type State = ();

    fn prepare(
        clear: Self::Clear,
        _state: Self::State,
        _rng: &mut dyn RngCore,
        ctx: &TestContext,
    ) -> (Self, Self::Clear) {
        let encrypted = ctx.cks.encrypt_bool(clear);
        (encrypted, clear)
    }

    fn as_ref(&self) -> Self::Ref<'_> {
        self
    }
}

impl TestInput for SignedRadixCiphertext {
    type Clear = Int;

    type Ref<'a>
        = &'a Self
    where
        Self: 'a;

    type State = RadixState;

    fn prepare(
        mut clear: Self::Clear,
        state: Self::State,
        _rng: &mut dyn RngCore,
        ctx: &TestContext,
    ) -> (Self, Self::Clear) {
        let n_blocks = ctx.num_blocks_for_bits(clear.bits()) as usize;
        let mut encrypted = ctx.cks.encrypt_signed_radix(clear.value(), n_blocks);

        match state {
            RadixState::Clean => {}
            RadixState::FullNoise => {
                saturate_noise(&ctx.cks.key, &ctx.cpu_sks.key, &mut encrypted.blocks);
                assert!(encrypted.block_carries_are_empty());
            }
            RadixState::Saturated => {
                saturate_noise(&ctx.cks.key, &ctx.cpu_sks.key, &mut encrypted.blocks);
                let added = saturate_degree(&ctx.cks.key, &ctx.cpu_sks.key, &mut encrypted.blocks);
                // The amount wraps at the radix width like the encrypted value does
                clear = clear.wrapping_add(Int::new(added as i128, clear.bits()));
                let dec: i128 = ctx.cks.decrypt_signed_radix(&encrypted);
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

impl TestInput for Vec<RadixCiphertext> {
    type Clear = Vec<Uint>;

    type Ref<'a>
        = &'a [RadixCiphertext]
    where
        Self: 'a;

    type State = RadixState;

    fn prepare(
        clear: Self::Clear,
        state: Self::State,
        rng: &mut dyn RngCore,
        ctx: &TestContext,
    ) -> (Self, Self::Clear) {
        let mut states = vec![RadixState::Clean; clear.len()];
        // An empty input has nothing to dirty, and the range below would be empty
        if state != RadixState::Clean && !clear.is_empty() {
            // Inclusive end so that a single element vec can be dirtied, and so that
            // the case where every element is dirty is reachable
            let n_dirty = rng.gen_range(1..=clear.len());
            let dirty_indices = (0..n_dirty).map(|_| rng.gen_range(0..clear.len()));

            for dirty_index in dirty_indices {
                states[dirty_index] = state;
            }
        }

        let mut prepared_radixes = Self::with_capacity(clear.len());
        let mut adjusted_clears = Vec::with_capacity(clear.len());
        for (clear_value, state) in clear.into_iter().zip(states) {
            let (prepared, adjusted_clear) =
                <RadixCiphertext as TestInput>::prepare(clear_value, state, rng, ctx);
            prepared_radixes.push(prepared);
            adjusted_clears.push(adjusted_clear);
        }

        (prepared_radixes, adjusted_clears)
    }

    fn as_ref(&self) -> Self::Ref<'_> {
        self.as_slice()
    }
}

/// Clear model of a radix ciphertext, [`Uint`] or [`Int`], as the scalar machinery sees it.
pub(crate) trait ClearInteger:
    Copy + Eq + std::fmt::Debug + std::fmt::Display + 'static
{
    /// The value reduced to `bits` bits.
    fn cast(self, bits: u32) -> Self;

    /// Zero, one and the bounds of a radix of `bits` bits.
    fn radix_edges(bits: u32) -> Vec<Self>;

    /// Scalars of `type_bits` bits worth testing against a radix of `radix_bits` bits: zero,
    /// one, the radix bounds, just past them, and the type bounds.
    ///
    /// "Just past" includes values with every radix bit set plus a single excess bit.
    /// Implementations decompose the scalar in blocks, and an excess confined to the block
    /// holding the radix's top bits, combined with a non zero in-range part, is a known blind
    /// spot that `radix_max + 1` alone does not exercise.
    ///
    /// Whatever the scalar type, a value that fits the radix blocks but not the radix range,
    /// with `n` the radix bit width: `[radix_max + 1, 2ⁿ[` and `[-2ⁿ, radix_min[` for a signed
    /// radix, `[-2ⁿ, 0[` for an unsigned one, is seen by an implementation working on the
    /// scalar reduced to the radix width as a value on the other side of the range, and the
    /// overflow flag it computes has to be flipped. The signed values include both ends of
    /// each band, `2ⁿ - 1` and `-2ⁿ`, which reduce to -1 and 0.
    fn scalar_edges(radix_bits: u32, type_bits: u32) -> Vec<Self>;

    /// Random scalar of `type_bits` bits: half of the draws fit in a radix of `radix_bits`
    /// bits, the other half exceed it (when the type allows).
    ///
    /// To pick values out of the radix range, 2 steps are involved:
    /// 1) Randomly pick a bit length in `radix_bits + 1..=type_bits`
    /// 2) Pick a random value needing exactly that many bits
    ///
    /// This is done this way to augment the chances of picking values that are "just" past
    /// the radix range, and not always values way beyond it.
    fn random_scalar(rng: &mut dyn RngCore, radix_bits: u32, type_bits: u32) -> Self;
}

impl ClearInteger for Uint {
    fn cast(self, bits: u32) -> Self {
        self.cast(bits)
    }

    fn radix_edges(bits: u32) -> Vec<Self> {
        let mut edges = vec![Self::zero(bits), Self::one(bits), Self::max(bits)];
        edges.dedup();
        edges
    }

    fn scalar_edges(radix_bits: u32, type_bits: u32) -> Vec<Self> {
        let type_max = Self::max(type_bits).value();
        let radix_max = Self::max(radix_bits).value();
        let mut values = vec![0, 1, radix_max, type_max];
        if radix_max < type_max {
            // radix_bits < type_bits, so the largest of these, 2^(radix_bits + 1) - 1, fits
            // in the type and in u128
            values.extend([radix_max + 1, radix_max + 2, 2 * radix_max + 1]);
        }
        values.sort_unstable();
        values.dedup();
        values
            .into_iter()
            .map(|value| Self::new(value, type_bits))
            .collect()
    }

    fn random_scalar(rng: &mut dyn RngCore, radix_bits: u32, type_bits: u32) -> Self {
        let radix_bits = radix_bits.min(type_bits);
        let value = if radix_bits < type_bits && rng.gen_bool(0.5) {
            let bit_length = rng.gen_range(radix_bits + 1..=type_bits);
            rng.gen_range(1u128 << (bit_length - 1)..=Self::max(bit_length).value())
        } else {
            rng.gen_range(0..=Self::max(radix_bits).value())
        };
        Self::new(value, type_bits)
    }
}

impl ClearInteger for Int {
    fn cast(self, bits: u32) -> Self {
        self.cast(bits)
    }

    fn radix_edges(bits: u32) -> Vec<Self> {
        let mut edges = vec![
            Self::min(bits),
            Self::new(-1, bits),
            Self::zero(bits),
            Self::one(bits),
            Self::max(bits),
        ];
        edges.dedup();
        edges
    }

    fn scalar_edges(radix_bits: u32, type_bits: u32) -> Vec<Self> {
        let type_range = Self::value_range(type_bits);
        let radix_min = Self::min(radix_bits).value();
        let radix_max = Self::max(radix_bits).value();
        let mut values = vec![
            0,
            1,
            -1,
            radix_min,
            radix_max,
            *type_range.start(),
            *type_range.end(),
        ];
        if radix_bits < type_bits {
            let candidates = [
                radix_max.checked_add(1),
                radix_max.checked_add(2),
                radix_min.checked_sub(1),
                radix_min.checked_sub(2),
                // Every radix bit set plus a single excess bit: 2^radix_bits - 1 and its
                // negative counterpart -2^radix_bits - 1, then 2^(radix_bits + 1) - 1
                Some(Self::max(radix_bits + 1).value()),
                Some(Self::min(radix_bits + 1).value()),
                Self::min(radix_bits + 1).value().checked_sub(1),
                (radix_bits + 2 <= MAX_RADIX_BITS).then(|| Self::max(radix_bits + 2).value()),
            ];
            values.extend(
                candidates
                    .into_iter()
                    .flatten()
                    .filter(|value| type_range.contains(value)),
            );
        }
        values.sort_unstable();
        values.dedup();
        values
            .into_iter()
            .map(|value| Self::new(value, type_bits))
            .collect()
    }

    fn random_scalar(rng: &mut dyn RngCore, radix_bits: u32, type_bits: u32) -> Self {
        let radix_bits = radix_bits.min(type_bits);
        let value = if radix_bits < type_bits && rng.gen_bool(0.5) {
            // A value needing exactly `bit_length` bits is in the range of `bit_length` bits
            // but out of the range of `bit_length - 1` bits, on either side of it
            let bit_length = rng.gen_range(radix_bits + 1..=type_bits);
            let inner = Self::value_range(bit_length - 1);
            let outer = Self::value_range(bit_length);
            if rng.gen_bool(0.5) {
                rng.gen_range(inner.end() + 1..=*outer.end())
            } else {
                rng.gen_range(*outer.start()..=inner.start() - 1)
            }
        } else {
            rng.gen_range(Self::value_range(radix_bits))
        };
        Self::new(value, type_bits)
    }
}

/// Rust scalar types accepted by the `scalar_*` operations, as seen by the harness.
pub(crate) trait ScalarType: Copy + std::fmt::Debug + 'static {
    const BITS: u32;
    /// The clear model matching the type's signedness.
    type Clear: ClearInteger;
    fn from_clear(value: Self::Clear) -> Self;
}

macro_rules! impl_scalar_type {
    ($clear:ty: $($ty:ty),+) => {
        $(
            impl ScalarType for $ty {
                const BITS: u32 = <$ty>::BITS;
                type Clear = $clear;

                fn from_clear(value: $clear) -> Self {
                    value.value() as $ty
                }
            }
        )+
    };
}

impl_scalar_type!(Uint: u8, u16, u32, u64, u128);
impl_scalar_type!(Int: i8, i16, i32, i64, i128);

/// Wraps a clear model to use `T::BITS` bits of precision
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
/// random scalar used will be in the range of a u64 (but stored on a [`Uint`]); with
/// `TestScalar<i64>` it is stored on an [`Int`].
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) struct TestScalar<T: ScalarType> {
    value: T::Clear,
    _marker: std::marker::PhantomData<T>,
}

impl<T: ScalarType> std::fmt::Debug for TestScalar<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TestScalar<{}>({})",
            std::any::type_name::<T>(),
            self.value
        )
    }
}

impl<T: ScalarType> TestScalar<T> {
    pub(crate) fn new(value: T::Clear) -> Self {
        Self {
            value: value.cast(T::BITS),
            _marker: std::marker::PhantomData,
        }
    }

    /// The scalar as a clear of `T::BITS` bits, for operations working at full precision
    /// (comparisons).
    pub(crate) fn clear(self) -> T::Clear {
        self.value
    }

    /// The scalar reduced to `bits` bits, i.e. what operations that truncate the scalar to
    /// the radix width see.
    pub(crate) fn cast(self, bits: u32) -> T::Clear {
        self.value.cast(bits)
    }

    fn to_scalar(self) -> T {
        T::from_clear(self.value)
    }
}

/// Fixed cases for an operation taking a single radix of `radix_bits` bits: its edge values
/// (see [`ClearInteger`]).
pub(crate) fn radix_edges_fixed_cases<C: ClearInteger>(
    size_requirements: SizeRequirements,
    ctx: &TestContext,
) -> Vec<(C,)> {
    C::radix_edges(ctx.radix_bits(size_requirements.n_blocks))
        .into_iter()
        .map(|value| (value,))
        .collect()
}

/// Fixed cases for an operation between two radixes of `radix_bits` bits: every edge value
/// against every other (see [`ClearInteger`]).
///
/// The product includes the pairs of equal values, which comparison-like operations treat
/// specially and random cases practically never draw.
pub(crate) fn radix_pair_fixed_cases<C: ClearInteger>(
    size_requirements: SizeRequirements,
    ctx: &TestContext,
) -> Vec<(C, C)> {
    let radix_bits = ctx.radix_bits(size_requirements.n_blocks);
    iproduct!(C::radix_edges(radix_bits), C::radix_edges(radix_bits)).collect()
}

/// Fixed cases for an operation between a radix of `radix_bits` bits and a scalar of type
/// `T`: the radix edges against the scalar edge values (see [`ClearInteger`]).
pub(crate) fn default_scalar_fixed_cases<T: ScalarType>(
    size_requirements: SizeRequirements,
    ctx: &TestContext,
) -> Vec<(T::Clear, TestScalar<T>)> {
    let radix_bits = ctx.radix_bits(size_requirements.n_blocks);
    let scalar_edges: Vec<TestScalar<T>> =
        <T::Clear as ClearInteger>::scalar_edges(radix_bits, T::BITS)
            .into_iter()
            .map(TestScalar::new)
            .collect();
    iproduct!(
        <T::Clear as ClearInteger>::radix_edges(radix_bits),
        scalar_edges
    )
    .collect()
}

/// Clear model of a shift or rotation amount
///
/// We use this type to have better control over the randomness
/// and other properties of values meant to be shift/rotation amounts
/// in the tests, for instance:
/// 'valid' shifts values are much smaller than other inputs.
/// e.g: on an 8 bit radix, shift values should be in range 0..=7, so in order to not always draw
/// random values that never exercise the valid range, we have this special wrapper type
/// that increase the draw of good shift amounts.
///
///
/// `A` is the type the operation takes it as:
/// [`RadixCiphertext`] for an encrypted amount
/// an unsigned scalar type for a clear one (e.g.: u128)
pub(crate) struct ShiftAmount<A> {
    value: Uint,
    _marker: std::marker::PhantomData<A>,
}

// Manual impl to skip the `_marker` which makes reports noisier
impl<A> std::fmt::Debug for ShiftAmount<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShiftAmount")
            .field("value", &self.value)
            .finish_non_exhaustive()
    }
}

// Not derived, as derives would require `A` itself to be `Copy`
impl<A> Clone for ShiftAmount<A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A> Copy for ShiftAmount<A> {}

impl<A> ShiftAmount<A> {
    fn new(value: Uint) -> Self {
        Self {
            value,
            _marker: std::marker::PhantomData,
        }
    }

    pub(crate) fn value(self) -> u128 {
        self.value.value()
    }
}

/// Random amount of at most `amount_bits` bits against a radix of `radix_bits` bits: half of
/// the draws shift by less than the width, the other half overshift.
fn random_shift_amount(rng: &mut dyn RngCore, radix_bits: u32, amount_bits: u32) -> u128 {
    assert!(
        radix_bits.ilog2() < amount_bits,
        "amounts of {amount_bits} bits cannot overshift a radix of {radix_bits} bits"
    );
    let width = u128::from(radix_bits);
    if rng.gen_bool(0.5) {
        rng.gen_range(0..width)
    } else {
        // As in `ClearInteger::random_scalar`, the bit length is drawn first so that amounts
        // just past the width are as likely as huge ones
        let bit_length = rng.gen_range(radix_bits.ilog2() + 1..=amount_bits);
        let low = (1u128 << (bit_length - 1)).max(width);
        rng.gen_range(low..=Uint::max(bit_length).value())
    }
}

impl<T: ScalarType<Clear = Uint>> TestClearInput for ShiftAmount<T> {
    type Input = ShiftAmountOperand<T>;

    fn generate_random(
        rng: &mut dyn RngCore,
        size_requirements: SizeRequirements,
        ctx: &TestContext,
    ) -> Self {
        let radix_bits = ctx.radix_bits(size_requirements.n_blocks);
        let value = random_shift_amount(rng, radix_bits, T::BITS);
        Self::new(Uint::new(value, T::BITS))
    }
}

/// A [`ShiftAmount`] as the operation receives it: the encrypted radix, or the scalar.
///
/// We also need this wrapper type in order to be able to exercise other properties
/// of the shift/rot APIs
pub(crate) struct ShiftAmountOperand<A>(A);

impl<T: ScalarType<Clear = Uint>> TestInput for ShiftAmountOperand<T> {
    type Clear = ShiftAmount<T>;

    type Ref<'a> = T;

    // Scalars have no state
    type State = ();

    fn prepare(
        clear: Self::Clear,
        _state: Self::State,
        _rng: &mut dyn RngCore,
        _ctx: &TestContext,
    ) -> (Self, Self::Clear) {
        (Self(T::from_clear(clear.value)), clear)
    }

    fn as_ref(&self) -> Self::Ref<'_> {
        self.0
    }
}

/// The APIs working with encrypted shift/rot amount allow the amount radix
/// to be encrypted on a number of block different that the radix being modified
/// (i.e we allow shift(radix_16_bits, amount_radix_6_bits)), this type serves
/// radixes of a different width
impl ShiftAmount<RadixCiphertext> {
    /// The fewest blocks of `bits_per_block` bits holding `value`, at least one.
    fn fewest_blocks(value: u128, bits_per_block: u32) -> u32 {
        (u128::BITS - value.leading_zeros())
            .div_ceil(bits_per_block)
            .max(1)
    }

    /// The amount a rotation of a radix of `radix_bits` bits by this encrypted amount
    /// actually rotates by, before the reduction modulo `radix_bits`.
    ///
    /// The implementation only reads the low ⌈log₂(radix_bits)⌉ bits of the amount, i.e. the
    /// amount modulo the power of two at or above `radix_bits`. When `radix_bits` is not a
    /// power of two, amounts past that power of two do not rotate as a reduction modulo the
    /// width would: rotating 6 bits by 8 is a rotation by 0, not by 2.
    pub(crate) fn rotation_amount(self, radix_bits: u32) -> u128 {
        self.value() % u128::from(radix_bits.next_power_of_two())
    }
}

impl TestClearInput for ShiftAmount<RadixCiphertext> {
    type Input = ShiftAmountOperand<RadixCiphertext>;

    fn generate_random(
        rng: &mut dyn RngCore,
        size_requirements: SizeRequirements,
        ctx: &TestContext,
    ) -> Self {
        let radix_bits = ctx.radix_bits(size_requirements.n_blocks);
        let value = random_shift_amount(rng, radix_bits, radix_bits);
        let n_blocks = if rng.gen_bool(0.5) {
            size_requirements.n_blocks
        } else {
            let fewest_blocks = Self::fewest_blocks(value, ctx.bits_per_block());
            rng.gen_range(fewest_blocks..=size_requirements.n_blocks)
        };
        Self::new(Uint::new(value, ctx.radix_bits(n_blocks)))
    }
}

impl TestInput for ShiftAmountOperand<RadixCiphertext> {
    type Clear = ShiftAmount<RadixCiphertext>;

    type Ref<'a> = &'a RadixCiphertext;

    type State = RadixState;

    fn prepare(
        clear: Self::Clear,
        state: Self::State,
        rng: &mut dyn RngCore,
        ctx: &TestContext,
    ) -> (Self, Self::Clear) {
        let (encrypted, value) = RadixCiphertext::prepare(clear.value, state, rng, ctx);
        (Self(encrypted), ShiftAmount::new(value))
    }

    fn as_ref(&self) -> Self::Ref<'_> {
        &self.0
    }
}

/// Fixed cases for a shift or a rotation of a radix of `radix_bits` bits by a scalar amount of
/// type `T`: the radix edges (see [`ClearInteger`]) against the amount edge values (see
/// [`scalar_shift_amount_edge_values`]).
pub(crate) fn scalar_shift_amount_fixed_cases<C: ClearInteger, T: ScalarType<Clear = Uint>>(
    size_requirements: SizeRequirements,
    ctx: &TestContext,
) -> Vec<(C, ShiftAmount<T>)> {
    let radix_bits = ctx.radix_bits(size_requirements.n_blocks);
    iproduct!(
        C::radix_edges(radix_bits),
        scalar_shift_amount_edge_values::<T>(radix_bits)
    )
    .collect()
}

/// Scalar shift and rotation amounts of type `T` worth testing against a radix of `radix_bits`
/// bits.
///
/// Tests amounts too wide for u32/u64 as we had a bug due to casting being used
/// truncating the values incorrectly
fn scalar_shift_amount_edge_values<T: ScalarType<Clear = Uint>>(
    radix_bits: u32,
) -> Vec<ShiftAmount<T>> {
    let bits = u128::from(radix_bits);
    let amount_max = Uint::max(T::BITS).value();
    let mut values = vec![
        0,
        1,
        2,
        3,
        bits / 2,
        bits - 1,
        bits,
        bits + 1,
        2 * bits - 1,
        amount_max,
    ];
    for low_bits in [u32::BITS, u64::BITS] {
        let wide = 1u128 << low_bits;
        values.extend([wide - 1, wide, wide + 1, wide + bits - 1]);
    }
    values.retain(|value| *value <= amount_max);
    values.sort_unstable();
    values.dedup();
    values
        .into_iter()
        .map(|value| ShiftAmount::new(Uint::new(value, T::BITS)))
        .collect()
}

/// Fixed cases for a shift or a rotation of a radix of `radix_bits` bits by an encrypted
/// amount: each amount edge value (see [`encrypted_shift_amount_edge_values`]) paired with one
/// radix edge (see [`ClearInteger`]), cycling through them.
///
/// Encrypted shifts are too costly to run the product of both sets at every block count. The
/// amount is what drives the implementation's paths, random cases diversify the values.
pub(crate) fn encrypted_shift_amount_fixed_cases<C: ClearInteger>(
    size_requirements: SizeRequirements,
    ctx: &TestContext,
) -> Vec<(C, ShiftAmount<RadixCiphertext>)> {
    let radix_bits = ctx.radix_bits(size_requirements.n_blocks);
    C::radix_edges(radix_bits)
        .into_iter()
        .cycle()
        .zip(encrypted_shift_amount_edge_values(
            radix_bits,
            ctx.bits_per_block(),
        ))
        .collect()
}

/// Encrypted shift and rotation amounts worth testing against a radix of `radix_bits` bits,
/// each on a radix of `radix_bits` bits and on the fewest blocks holding it.
///
/// On top of the edges around the width, the implementation splits the amount: its low
/// ⌈log₂(radix_bits)⌉ bits drive the shifter, the overshift is decided on the whole amount.
/// So the amounts include the first ones the shifter cannot see, and the top bit alone,
/// which overshifts with low bits all zero. On the fewest blocks, small amounts have fewer
/// bits than the shifter reads.
fn encrypted_shift_amount_edge_values(
    radix_bits: u32,
    bits_per_block: u32,
) -> Vec<ShiftAmount<RadixCiphertext>> {
    let bits = u128::from(radix_bits);
    let shifter_range = u128::from(radix_bits.next_power_of_two());
    let amount_max = Uint::max(radix_bits).value();
    let mut values = vec![
        0,
        1,
        2,
        3,
        bits / 2,
        bits - 1,
        bits,
        bits + 1,
        2 * bits - 1,
        shifter_range - 1,
        shifter_range,
        shifter_range + 1,
        1 << (radix_bits - 1),
        amount_max,
    ];
    values.retain(|value| *value <= amount_max);
    values.sort_unstable();
    values.dedup();
    values
        .into_iter()
        .flat_map(|value| {
            let fewest_bits = ShiftAmount::<RadixCiphertext>::fewest_blocks(value, bits_per_block)
                * bits_per_block;
            let narrower = (fewest_bits < radix_bits).then_some(fewest_bits);
            std::iter::once(radix_bits)
                .chain(narrower)
                .map(move |bits| ShiftAmount::new(Uint::new(value, bits)))
        })
        .collect()
}

impl<T: ScalarType> TestClearInput for TestScalar<T> {
    type Input = T;

    fn generate_random(
        rng: &mut dyn RngCore,
        size_requirements: SizeRequirements,
        ctx: &TestContext,
    ) -> Self {
        Self::new(<T::Clear as ClearInteger>::random_scalar(
            rng,
            ctx.radix_bits(size_requirements.n_blocks),
            T::BITS,
        ))
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

impl_test_input_for_scalar!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

/// Implements the [`TestInput`] trait for tuples, this is how we handle
/// different arity (unary, binary)
macro_rules! impl_test_input_for_tuple {
    ($($ty:ident . $idx:tt),+) => {
        impl<$($ty),+> TestClearInput for ($($ty,)+)
        where
            $($ty: TestClearInput,)+
        {
            type Input = ($($ty::Input,)+);

            fn generate_random(rng: &mut dyn RngCore, size_requirements: SizeRequirements, ctx: &TestContext) -> Self {
                ($($ty::generate_random(rng, size_requirements, ctx),)+)
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
impl_test_input_for_tuple!(A.0, B.1, C.2);

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

impl<T> TestOutput for Option<T>
where
    T: TestOutput + std::fmt::Debug,
    T::Clear: std::fmt::Debug,
{
    type Clear = Option<T::Clear>;

    fn validate(&self, expected: Self::Clear, ctx: &TestContext, failures: &mut FailureSink) {
        match (self, expected) {
            (Some(value), Some(expected)) => {
                <T as TestOutput>::validate(value, expected, ctx, failures);
            }
            (None, expected @ Some(_)) => failures.push(FailureKind::ValueMismatch {
                expected: format!("{expected:?}"),
                got: "None".to_string(),
            }),
            (Some(_), None) => failures.push(FailureKind::ValueMismatch {
                expected: "None".to_string(),
                got: format!("{self:?}"),
            }),
            (None, None) => {
                // Valid
            }
        }
    }
}

impl TestOutput for SignedRadixCiphertext {
    type Clear = Int;

    fn validate(&self, expected: Self::Clear, ctx: &TestContext, failures: &mut FailureSink) {
        let expected_n_blocks = ctx.num_blocks_for_bits(expected.bits());
        if self.blocks.len() as u32 != expected_n_blocks {
            failures.push(FailureKind::BlockCountMismatch {
                expected: expected_n_blocks,
                got: self.blocks.len() as u32,
            });
        }

        let decrypted: i128 = ctx.cks.decrypt_signed_radix(self);
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
impl_execute_on_for_tuple!(A.0, B.1, C.2);

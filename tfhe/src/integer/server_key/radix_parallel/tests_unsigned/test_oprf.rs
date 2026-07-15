use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::commons::math::random::tests::{
    cumulate, dkw_alpha_from_epsilon, sup_diff,
};
use crate::integer::ciphertext::{
    PrfReRandomizationContext, RadixCiphertext, ReRandomizationHashAlgo, ReRandomizationKey,
    ReRandomizationSeedHasher, SignedRadixCiphertext,
};
use crate::integer::keycache::KEY_CACHE;
use crate::integer::oprf::{OprfPrivateKey, OprfServerKey};
use crate::integer::server_key::radix_parallel::tests_long_run::OpSequenceFunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuOprfExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::{
    gen_keys, ClientKey, CompactPrivateKey, CompactPublicKey, IntegerKeyKind, RadixClientKey,
    ServerKey,
};
use crate::shortint::parameters::test_params::{
    TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
};
use crate::shortint::parameters::*;
use crate::shortint::OprfSeed;
use crate::Tag;
use rand::Rng;
use statrs::distribution::ContinuousCDF;
use std::collections::HashMap;
use std::num::NonZeroU64;
use tfhe_csprng::generators::DefaultRandomGenerator;
use tfhe_csprng::seeders::Seed;

create_parameterized_test!(oprf_uniformity_unsigned {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128
});
create_parameterized_test!(oprf_any_range_unsigned {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128
});
create_parameterized_test!(oprf_almost_uniformity_unsigned {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128
});

create_parameterized_test!(pseudo_random_integer_and_rerand {
    TEST_PARAM_MULTI_BIT_GROUP_3_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    TEST_PARAM_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128
});

fn oprf_uniformity_unsigned<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor =
        CpuOprfExecutor::new(&|oprf_key: &OprfServerKey,
                               seed: Seed,
                               random_bits_count: u64,
                               num_blocks: u64,
                               sk: &ServerKey| {
            oprf_key.par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                seed,
                random_bits_count,
                num_blocks,
                sk,
            )
        });
    oprf_uniformity_test(param, executor);
}

fn oprf_any_range_unsigned<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor =
        CpuOprfExecutor::new(&|oprf_key: &OprfServerKey,
                               seed: Seed,
                               num_input_random_bits: u64,
                               excluded_upper_bound: u64,
                               num_blocks_output: u64,
                               sk: &ServerKey| {
            oprf_key.par_generate_oblivious_pseudo_random_unsigned_custom_range(
                seed,
                num_input_random_bits,
                NonZeroU64::new(excluded_upper_bound).unwrap(),
                num_blocks_output,
                sk,
            )
        });
    oprf_any_range_test(param, executor);
}

fn oprf_almost_uniformity_unsigned<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor =
        CpuOprfExecutor::new(&|oprf_key: &OprfServerKey,
                               seed: Seed,
                               num_input_random_bits: u64,
                               excluded_upper_bound: u64,
                               num_blocks_output: u64,
                               sk: &ServerKey| {
            oprf_key.par_generate_oblivious_pseudo_random_unsigned_custom_range(
                seed,
                num_input_random_bits,
                NonZeroU64::new(excluded_upper_bound).unwrap(),
                num_blocks_output,
                sk,
            )
        });
    oprf_almost_uniformity_test(param, executor);
}

pub(crate) fn square(a: f64) -> f64 {
    a * a
}

pub(crate) fn uniformity_p_value<F>(f: F, sample_count: usize, distinct_values: u64) -> f64
where
    F: FnMut(usize) -> u64,
{
    let values: Vec<_> = (0..sample_count).map(f).collect();
    let mut values_count = HashMap::new();
    for i in &values {
        *values_count.entry(i).or_insert(0) += 1;
    }

    let single_expected_count = sample_count as f64 / distinct_values as f64;

    let distance: f64 = (0..distinct_values)
        .map(|value| *values_count.get(&value).unwrap_or(&0))
        .map(|count| square(count as f64 - single_expected_count) / single_expected_count)
        .sum();

    statrs::distribution::ChiSquared::new((distinct_values - 1) as f64)
        .unwrap()
        .sf(distance)
}

pub(crate) fn internal_test_uniformity<F>(
    sample_count: usize,
    p_value_limit: f64,
    distinct_values: u64,
    f: F,
) where
    F: FnMut(usize) -> u64,
{
    let p_value = uniformity_p_value(f, sample_count, distinct_values);
    assert!(
        p_value_limit < p_value,
        "p_value (={p_value}) expected to be bigger than {p_value_limit}"
    );
}

pub(crate) fn setup_oprf_test<I, O, E>(
    param: impl Into<TestParameters>,
    executor: &mut E,
) -> RadixClientKey
where
    E: OpSequenceFunctionExecutor<I, O>,
{
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);
    let oprf_priv_key = OprfPrivateKey::new(&cks);

    let mut rng = rand::thread_rng();
    let seed: u128 = rng.gen();
    println!("seed: {seed:?}");
    let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(Seed(seed));
    let temp_cks = crate::ClientKey::from_raw_parts(
        cks.clone(),
        None,
        None,
        None,
        None,
        None,
        Some(oprf_priv_key),
        Tag::default(),
    );
    let comp_sks = crate::CompressedServerKey::new(&temp_cks);
    let cks = RadixClientKey::from((cks, 1));
    executor.setup(&cks, &comp_sks, &mut deterministic_seeder);
    cks
}

pub(crate) fn oprf_uniformity_test<P, E>(param: P, mut executor: E)
where
    P: Into<TestParameters>,
    E: OpSequenceFunctionExecutor<(Seed, u64, u64), RadixCiphertext>,
{
    let cks = setup_oprf_test(param, &mut executor);

    let sample_count: usize = 10_000;
    let p_value_limit: f64 = 0.000_01;
    let random_bits_count = 3;
    let num_blocks = 2;
    let distinct_values = 1u64 << random_bits_count;

    internal_test_uniformity(sample_count, p_value_limit, distinct_values, |seed| {
        let img: RadixCiphertext =
            executor.execute((Seed(seed as u128), random_bits_count, num_blocks as u64));
        cks.decrypt(&img)
    });
}

pub(crate) fn oprf_any_range_test<P, E>(param: P, mut executor: E)
where
    P: Into<TestParameters>,
    E: OpSequenceFunctionExecutor<(Seed, u64, u64, u64), RadixCiphertext>,
{
    let cks = setup_oprf_test(param, &mut executor);

    let num_loops = 100;

    for s in 0..num_loops {
        let seed = Seed(s);

        for num_input_random_bits in [1, 2, 63, 64] {
            for (excluded_upper_bound, num_blocks_output) in [(3, 1), (3, 32), ((1 << 32) + 1, 64)]
            {
                let img = executor.execute((
                    seed,
                    num_input_random_bits,
                    excluded_upper_bound,
                    num_blocks_output as u64,
                ));

                assert_eq!(img.blocks.len(), num_blocks_output);

                let decrypted: u64 = cks.decrypt(&img);

                assert!(decrypted < excluded_upper_bound);
            }
        }
    }
}

pub(crate) fn oprf_almost_uniformity_test<P, E>(param: P, mut executor: E)
where
    P: Into<TestParameters>,
    E: OpSequenceFunctionExecutor<(Seed, u64, u64, u64), RadixCiphertext>,
{
    let cks = setup_oprf_test(param, &mut executor);

    let sample_count: usize = 10_000;
    let p_value_limit: f64 = 0.001;
    let num_input_random_bits: u64 = 4;
    let num_blocks_output = 64;
    let excluded_upper_bound = 10;

    let values: Vec<u64> = (0..sample_count)
        .map(|seed| {
            let img = executor.execute((
                Seed(seed as u128),
                num_input_random_bits,
                excluded_upper_bound,
                num_blocks_output,
            ));
            cks.decrypt(&img)
        })
        .collect();

    let p_value_upper_bound = p_value_upper_bound_oprf_almost_uniformity_from_values(
        &values,
        num_input_random_bits,
        excluded_upper_bound,
    );

    assert!(p_value_limit < p_value_upper_bound);
}

pub(crate) fn p_value_upper_bound_oprf_almost_uniformity_from_values(
    values: &[u64],
    num_input_random_bits: u64,
    excluded_upper_bound: u64,
) -> f64 {
    let density = oprf_density_function(excluded_upper_bound, num_input_random_bits);

    let theoretical_pdf = probability_density_function_from_density(&density);

    let mut bins = vec![0_u64; excluded_upper_bound as usize];
    for value in values.iter().copied() {
        bins[value as usize] += 1;
    }

    let cumulative_bins = cumulate(&bins);
    let theoretical_cdf = cumulate(&theoretical_pdf);
    let sup_diff = sup_diff(&cumulative_bins, &theoretical_cdf);

    dkw_alpha_from_epsilon(values.len() as f64, sup_diff)
}

pub(crate) fn oprf_density_function(
    excluded_upper_bound: u64,
    num_input_random_bits: u64,
) -> Vec<usize> {
    let random_input_upper_bound = 1 << num_input_random_bits;

    let mut density = vec![0_usize; excluded_upper_bound as usize];

    for i in 0..random_input_upper_bound {
        let output = ((i * excluded_upper_bound) >> num_input_random_bits) as usize;

        density[output] += 1;
    }
    density
}

pub(crate) fn probability_density_function_from_density(density: &[usize]) -> Vec<f64> {
    let total_count: usize = density.iter().copied().sum();

    density
        .iter()
        .map(|count| *count as f64 / total_count as f64)
        .collect()
}

// PRF rerand below

pub(crate) trait OprfReRandTestRunner {
    /// Builds the compute, OPRF and re-randomization keys for `param` and returns the client key
    /// used to decrypt the results.
    ///
    /// Re-randomization being tested independently too we only manage the Derived CPK case.
    fn setup(&mut self, param: TestParameters) -> ClientKey;

    /// Return the prf output once without and once with re-randomization.
    fn unsigned_full(
        &mut self,
        prf_seed: impl OprfSeed,
        num_blocks: u64,
        prf_re_randomization_context: &PrfReRandomizationContext,
    ) -> (RadixCiphertext, RadixCiphertext);

    /// Return the prf output once without and once with re-randomization.
    fn unsigned_bounded(
        &mut self,
        prf_seed: impl OprfSeed,
        random_bit_count: u64,
        num_blocks: u64,
        prf_re_randomization_context: &PrfReRandomizationContext,
    ) -> (RadixCiphertext, RadixCiphertext);

    /// Re-randomizing custom-range generation.
    ///
    /// Returns `None` on backends that do not expose a re-randomizing custom-range primitive yet
    /// (currently the GPU backend), in which case the generic test skips this sub-test.
    fn unsigned_custom_range(
        &mut self,
        prf_seed: impl OprfSeed,
        num_input_random_bits: u64,
        excluded_upper_bound: NonZeroU64,
        num_blocks_output: u64,
        prf_re_randomization_context: &PrfReRandomizationContext,
    ) -> (RadixCiphertext, RadixCiphertext);

    /// Return the prf output once without and once with re-randomization.
    fn signed_full(
        &mut self,
        prf_seed: impl OprfSeed,
        num_blocks: u64,
        prf_re_randomization_context: &PrfReRandomizationContext,
    ) -> (SignedRadixCiphertext, SignedRadixCiphertext);

    /// Return the prf output once without and once with re-randomization.
    fn signed_bounded(
        &mut self,
        prf_seed: impl OprfSeed,
        random_bit_count: u64,
        num_blocks: u64,
        prf_re_randomization_context: &PrfReRandomizationContext,
    ) -> (SignedRadixCiphertext, SignedRadixCiphertext);
}

/// CPU implementation of [`OprfReRandTestRunner`].
///
/// Uses a derived compact public key (no key-switch) for re-randomization.
pub(crate) struct CpuOprfReRandTestRunner {
    state: Option<CpuOprfReRandState>,
}

struct CpuOprfReRandState {
    sks: ServerKey,
    oprf_sks: OprfServerKey,
    rerand_cpk: CompactPublicKey,
}

impl CpuOprfReRandState {
    fn rerand_key(&self) -> ReRandomizationKey<'_> {
        ReRandomizationKey::DerivedCPKWithoutKeySwitch {
            cpk: &self.rerand_cpk,
        }
    }
}

impl CpuOprfReRandTestRunner {
    pub(crate) fn new() -> Self {
        Self { state: None }
    }

    fn state(&self) -> &CpuOprfReRandState {
        self.state.as_ref().expect("setup was not properly called")
    }
}

impl OprfReRandTestRunner for CpuOprfReRandTestRunner {
    fn setup(&mut self, param: TestParameters) -> ClientKey {
        let (cks, sks) = gen_keys(param, IntegerKeyKind::Radix);

        // Derived compact public key, re-using the compute secret key
        // legacy rerand not covered by this test
        let privk: CompactPrivateKey<&[u64]> = (&cks).try_into().unwrap();
        let rerand_cpk = CompactPublicKey::new(&privk);

        let oprf_cks = OprfPrivateKey::new(&cks);
        let oprf_sks = OprfServerKey::new(&oprf_cks, &cks).unwrap();

        self.state = Some(CpuOprfReRandState {
            sks,
            oprf_sks,
            rerand_cpk,
        });

        cks
    }

    fn unsigned_full(
        &mut self,
        prf_seed: impl OprfSeed,
        num_blocks: u64,
        prf_re_randomization_context: &PrfReRandomizationContext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let state = self.state();
        let rerand_key = state.rerand_key();

        let prf_seed = prf_seed.into_bytes();
        let prf_seed = prf_seed.as_ref();

        let prf_not_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_unsigned_integer(
                prf_seed, num_blocks, &state.sks,
            );
        let prf_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_unsigned_integer_and_re_randomize(
                prf_seed,
                num_blocks,
                &state.sks,
                &rerand_key,
                prf_re_randomization_context,
            )
            .unwrap();

        (prf_not_rerand, prf_rerand)
    }

    fn unsigned_bounded(
        &mut self,
        prf_seed: impl OprfSeed,
        random_bit_count: u64,
        num_blocks: u64,
        prf_re_randomization_context: &PrfReRandomizationContext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let state = self.state();
        let rerand_key = state.rerand_key();

        let prf_seed = prf_seed.into_bytes();
        let prf_seed = prf_seed.as_ref();

        let prf_not_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                prf_seed,
                random_bit_count,
                num_blocks,
                &state.sks,
            );
        let prf_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_unsigned_integer_bounded_and_re_randomize(
                prf_seed,
                random_bit_count,
                num_blocks,
                &state.sks,
                &rerand_key,
                prf_re_randomization_context,
            )
            .unwrap();

        (prf_not_rerand, prf_rerand)
    }

    fn unsigned_custom_range(
        &mut self,
        prf_seed: impl OprfSeed,
        num_input_random_bits: u64,
        excluded_upper_bound: NonZeroU64,
        num_blocks_output: u64,
        prf_re_randomization_context: &PrfReRandomizationContext,
    ) -> (RadixCiphertext, RadixCiphertext) {
        let state = self.state();
        let rerand_key = state.rerand_key();

        let prf_seed = prf_seed.into_bytes();
        let prf_seed = prf_seed.as_ref();

        let prf_not_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_unsigned_custom_range(
                prf_seed,
                num_input_random_bits,
                excluded_upper_bound,
                num_blocks_output,
                &state.sks,
            );
        let prf_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_unsigned_custom_range_and_re_randomize(
                prf_seed,
                num_input_random_bits,
                excluded_upper_bound,
                num_blocks_output,
                &state.sks,
                &rerand_key,
                prf_re_randomization_context,
            )
            .unwrap();

        (prf_not_rerand, prf_rerand)
    }

    fn signed_full(
        &mut self,
        prf_seed: impl OprfSeed,
        num_blocks: u64,
        prf_re_randomization_context: &PrfReRandomizationContext,
    ) -> (SignedRadixCiphertext, SignedRadixCiphertext) {
        let state = self.state();
        let rerand_key = state.rerand_key();

        let prf_seed = prf_seed.into_bytes();
        let prf_seed = prf_seed.as_ref();

        let prf_not_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_signed_integer(prf_seed, num_blocks, &state.sks);
        let prf_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_signed_integer_and_re_randomize(
                prf_seed,
                num_blocks,
                &state.sks,
                &rerand_key,
                prf_re_randomization_context,
            )
            .unwrap();

        (prf_not_rerand, prf_rerand)
    }

    fn signed_bounded(
        &mut self,
        prf_seed: impl OprfSeed,
        random_bit_count: u64,
        num_blocks: u64,
        prf_re_randomization_context: &PrfReRandomizationContext,
    ) -> (SignedRadixCiphertext, SignedRadixCiphertext) {
        let state = self.state();
        let rerand_key = state.rerand_key();

        let prf_seed = prf_seed.into_bytes();
        let prf_seed = prf_seed.as_ref();

        let prf_not_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_signed_integer_bounded(
                prf_seed,
                random_bit_count,
                num_blocks,
                &state.sks,
            );
        let prf_rerand = state
            .oprf_sks
            .par_generate_oblivious_pseudo_random_signed_integer_bounded_and_re_randomize(
                prf_seed,
                random_bit_count,
                num_blocks,
                &state.sks,
                &rerand_key,
                prf_re_randomization_context,
            )
            .unwrap();

        (prf_not_rerand, prf_rerand)
    }
}

#[track_caller]
fn check_unsigned_value_and_re_rand_are_ok(
    lhs: &RadixCiphertext,
    rhs: &RadixCiphertext,
    cks: &ClientKey,
    random_block_count: usize,
) -> u128 {
    let lhs_blocks = &lhs.blocks;
    let rhs_blocks = &rhs.blocks;

    assert_eq!(lhs_blocks.len(), rhs_blocks.len());
    let message_bits: u64 = cks.parameters().message_modulus().0.ilog2().into();
    let ct_bits = lhs_blocks.len() as u64 * message_bits;

    assert!(
        ct_bits <= u128::BITS as u64,
        "ciphertext too large to decrypt properly"
    );

    let dec_lhs: u128 = cks.decrypt_radix(lhs);
    let dec_rhs: u128 = cks.decrypt_radix(rhs);

    assert_eq!(dec_lhs, dec_rhs);

    // The total number of blocks can be larger than the random bit count for bounded cases
    for (idx, (lhs_block, rhs_block)) in lhs_blocks.iter().zip(rhs_blocks.iter()).enumerate() {
        if idx < random_block_count {
            assert_ne!(
                lhs_block.ct.as_ref(),
                rhs_block.ct.as_ref(),
                "Error verifying block #{idx} differ in lhs and rhs"
            );
        } else {
            // Upper blocks which are not random are trivial 0s;
            assert_eq!(lhs_block.ct.as_ref(), rhs_block.ct.as_ref());
            // Checks noise and masks are 0
            assert!(lhs_block.is_trivial());
            // Body of the LWE is also 0
            assert_eq!(*lhs_block.ct.get_body().data, 0);
            let noise_degree = lhs_block.noise_degree();
            // Degree is properly 0
            assert_eq!(noise_degree.degree.0, 0);
        }
    }

    dec_lhs
}

fn subtest_unsigned_integer_full<TestRunner: OprfReRandTestRunner>(
    prf_seed: impl OprfSeed,
    cks: &ClientKey,
    test_runner: &mut TestRunner,
    prf_re_randomization_context: &PrfReRandomizationContext,
) {
    const OUTPUT_BIT_COUNT: u64 = 16;

    let prf_seed = prf_seed.into_bytes();
    let prf_seed = prf_seed.as_ref();

    let message_bits: u64 = cks.parameters().message_modulus().0.ilog2().into();

    let num_blocks = OUTPUT_BIT_COUNT.div_ceil(message_bits);

    let (prf_not_rerand, prf_rerand) =
        test_runner.unsigned_full(prf_seed, num_blocks, prf_re_randomization_context);

    assert_eq!(prf_not_rerand.blocks.len() as u64, num_blocks);
    assert_eq!(prf_rerand.blocks.len() as u64, num_blocks);

    let decrypted = check_unsigned_value_and_re_rand_are_ok(
        &prf_not_rerand,
        &prf_rerand,
        cks,
        num_blocks as usize,
    );

    let random_value_range = 0..1 << OUTPUT_BIT_COUNT;
    assert!(
        random_value_range.contains(&decrypted),
        "range: {random_value_range:?}, decrypted: {decrypted}"
    );
}

fn subtest_unsigned_integer_bounded<TestRunner: OprfReRandTestRunner>(
    prf_seed: impl OprfSeed,
    cks: &ClientKey,
    test_runner: &mut TestRunner,
    prf_re_randomization_context: &PrfReRandomizationContext,
) {
    let mut rng = rand::thread_rng();
    const OUTPUT_BIT_COUNT: u64 = 16;

    let message_bits: u64 = cks.parameters().message_modulus().0.ilog2().into();

    let num_blocks = OUTPUT_BIT_COUNT.div_ceil(message_bits);
    let random_bit_count_range = 1..=OUTPUT_BIT_COUNT;
    let random_bit_count = rng.gen_range(random_bit_count_range);
    let random_value_range = 0..=1 << random_bit_count;
    let random_block_count = random_bit_count.div_ceil(message_bits);

    let (prf_not_rerand, prf_rerand) = test_runner.unsigned_bounded(
        prf_seed,
        random_bit_count,
        num_blocks,
        prf_re_randomization_context,
    );

    assert_eq!(prf_not_rerand.blocks.len() as u64, num_blocks);
    assert_eq!(prf_rerand.blocks.len() as u64, num_blocks);

    let decrypted = check_unsigned_value_and_re_rand_are_ok(
        &prf_not_rerand,
        &prf_rerand,
        cks,
        random_block_count as usize,
    );

    assert!(
        random_value_range.contains(&decrypted),
        "range: {random_value_range:?}, decrypted: {decrypted}"
    );
}

fn subtest_integer_bounded_padding_stays_trivial<TestRunner: OprfReRandTestRunner>(
    prf_seed: impl OprfSeed,
    cks: &ClientKey,
    test_runner: &mut TestRunner,
    prf_re_randomization_context: &PrfReRandomizationContext,
) {
    let mut rng = rand::thread_rng();
    const OUTPUT_BIT_COUNT: u64 = 16;

    let prf_seed = prf_seed.into_bytes();
    let prf_seed = prf_seed.as_ref();

    let message_bits: u64 = cks.parameters().message_modulus().0.ilog2().into();

    let num_blocks = OUTPUT_BIT_COUNT.div_ceil(message_bits);
    // at most num_blocks - 1 of random to leave at least one block of trivial padding
    let random_bit_count_range = 1..=(num_blocks - 1) * message_bits;
    let random_bit_count = rng.gen_range(random_bit_count_range);
    let random_block_count = random_bit_count.div_ceil(message_bits);

    {
        let (prf_not_rerand, prf_rerand) = test_runner.unsigned_bounded(
            prf_seed,
            random_bit_count,
            num_blocks,
            prf_re_randomization_context,
        );

        assert!(
            prf_not_rerand.blocks[random_block_count as usize..]
                .iter()
                .all(|ct| ct.is_trivial()),
            "Expected all padding blocks to be trivial 0s"
        );
        assert!(
            prf_rerand.blocks[random_block_count as usize..]
                .iter()
                .all(|ct| ct.is_trivial()),
            "Expected all padding blocks to be trivial 0s"
        );
    }

    {
        let (prf_not_rerand, prf_rerand) = test_runner.signed_bounded(
            prf_seed,
            random_bit_count,
            num_blocks,
            prf_re_randomization_context,
        );

        assert!(
            prf_not_rerand.blocks[random_block_count as usize..]
                .iter()
                .all(|ct| ct.is_trivial()),
            "Expected all padding blocks to be trivial 0s"
        );
        assert!(
            prf_rerand.blocks[random_block_count as usize..]
                .iter()
                .all(|ct| ct.is_trivial()),
            "Expected all padding blocks to be trivial 0s"
        );
    }
}

fn subtest_unsigned_integer_custom_range<TestRunner: OprfReRandTestRunner>(
    prf_seed: impl OprfSeed,
    cks: &ClientKey,
    test_runner: &mut TestRunner,
    prf_re_randomization_context: &PrfReRandomizationContext,
) {
    let mut rng = rand::thread_rng();
    // INPUT_RANDOM_BIT_COUNT needs to be >= OUTPUT_BIT_COUNT for the checks we run (it also makes
    // no sense in production to generate less bits than what the output value can hold since you
    // would not be able to generate all the possible values of the range)
    const INPUT_RANDOM_BIT_COUNT: u64 = 16;
    const OUTPUT_BIT_COUNT: u64 = 16;

    let message_bits: u64 = cks.parameters().message_modulus().0.ilog2().into();

    let output_num_blocks = OUTPUT_BIT_COUNT.div_ceil(message_bits);
    let excluded_upper_bound = {
        let mut result = NonZeroU64::new(rng.gen_range(1..=1 << OUTPUT_BIT_COUNT)).unwrap();

        // Custom range does not accept power of two range, since other primitives are more
        // efficient
        while result.is_power_of_two() {
            result = NonZeroU64::new(rng.gen_range(1..=1 << OUTPUT_BIT_COUNT)).unwrap();
        }

        result
    };

    println!("excluded_upper_bound={excluded_upper_bound:?}");

    let random_value_range = 0u128..excluded_upper_bound.get().into();
    // range_excluded_upper_bound is not a power of 2, get how many bits are necessary to
    // represent it via the ceil log2
    let excluded_upper_bound_log2: u64 = excluded_upper_bound.ilog2().into();
    let excluded_upper_bound_ceil_log2 = excluded_upper_bound_log2 + 1;
    let random_block_count = excluded_upper_bound_ceil_log2.div_ceil(message_bits);

    let (prf_not_rerand, prf_rerand) = test_runner.unsigned_custom_range(
        prf_seed,
        INPUT_RANDOM_BIT_COUNT,
        excluded_upper_bound,
        output_num_blocks,
        prf_re_randomization_context,
    );

    assert_eq!(prf_not_rerand.blocks.len() as u64, output_num_blocks);
    assert_eq!(prf_rerand.blocks.len() as u64, output_num_blocks);

    let decrypted = check_unsigned_value_and_re_rand_are_ok(
        &prf_not_rerand,
        &prf_rerand,
        cks,
        random_block_count as usize,
    );

    assert!(
        random_value_range.contains(&decrypted),
        "range: {random_value_range:?}, decrypted: {decrypted}"
    );
}

#[track_caller]
fn check_signed_value_and_re_rand_are_ok(
    lhs: &SignedRadixCiphertext,
    rhs: &SignedRadixCiphertext,
    cks: &ClientKey,
    random_block_count: usize,
) -> i128 {
    let lhs_blocks = &lhs.blocks;
    let rhs_blocks = &rhs.blocks;

    assert_eq!(lhs_blocks.len(), rhs_blocks.len());
    let message_bits: u64 = cks.parameters().message_modulus().0.ilog2().into();
    let ct_bits = lhs_blocks.len() as u64 * message_bits;

    // The total number of blocks can be larger than the random bit count for bounded cases
    for (idx, (lhs_block, rhs_block)) in lhs_blocks.iter().zip(rhs_blocks.iter()).enumerate() {
        if idx < random_block_count {
            assert_ne!(
                lhs_block.ct.as_ref(),
                rhs_block.ct.as_ref(),
                "Error verifying block #{idx} differ in lhs and rhs"
            );
        } else {
            // Upper blocks which are not random are trivial 0s;
            assert_eq!(lhs_block.ct.as_ref(), rhs_block.ct.as_ref());
            assert!(lhs_block.ct.as_ref().iter().all(|&x| x == 0))
        }
    }

    assert!(
        ct_bits <= i128::BITS as u64,
        "ciphertext too large to decrypt properly"
    );

    let dec_lhs: i128 = cks.decrypt_signed_radix(lhs);
    let dec_rhs: i128 = cks.decrypt_signed_radix(rhs);

    assert_eq!(dec_lhs, dec_rhs);

    dec_lhs
}

fn subtest_signed_integer_full<TestRunner: OprfReRandTestRunner>(
    prf_seed: impl OprfSeed,
    cks: &ClientKey,
    test_runner: &mut TestRunner,
    prf_re_randomization_context: &PrfReRandomizationContext,
) {
    const OUTPUT_BIT_COUNT: u64 = 16;

    let message_bits: u64 = cks.parameters().message_modulus().0.ilog2().into();

    let num_blocks = OUTPUT_BIT_COUNT.div_ceil(message_bits);

    let (prf_not_rerand, prf_rerand) =
        test_runner.signed_full(prf_seed, num_blocks, prf_re_randomization_context);

    assert_eq!(prf_not_rerand.blocks.len() as u64, num_blocks);
    assert_eq!(prf_rerand.blocks.len() as u64, num_blocks);

    let decrypted = check_signed_value_and_re_rand_are_ok(
        &prf_not_rerand,
        &prf_rerand,
        cks,
        num_blocks as usize,
    );

    let random_value_range = -1i128 << (OUTPUT_BIT_COUNT - 1)..1 << (OUTPUT_BIT_COUNT - 1);
    assert!(
        random_value_range.contains(&decrypted),
        "range: {random_value_range:?}, decrypted: {decrypted}"
    );
}

fn subtest_signed_integer_bounded<TestRunner: OprfReRandTestRunner>(
    prf_seed: impl OprfSeed,
    cks: &ClientKey,
    test_runner: &mut TestRunner,
    prf_re_randomization_context: &PrfReRandomizationContext,
) {
    let mut rng = rand::thread_rng();
    const OUTPUT_BIT_COUNT: u64 = 16;

    let message_bits: u64 = cks.parameters().message_modulus().0.ilog2().into();

    let num_blocks = OUTPUT_BIT_COUNT.div_ceil(message_bits);
    // For signed values on n_bits we need to stay < 2^(n_bits - 1)
    // since that value is a signed negative value
    let random_bit_count_range = 1..=(OUTPUT_BIT_COUNT - 1);
    let random_bit_count = rng.gen_range(random_bit_count_range);
    let random_value_range = 0..=1 << random_bit_count;
    let random_block_count = random_bit_count.div_ceil(message_bits);

    let (prf_not_rerand, prf_rerand) = test_runner.signed_bounded(
        prf_seed,
        random_bit_count,
        num_blocks,
        prf_re_randomization_context,
    );

    assert_eq!(prf_not_rerand.blocks.len() as u64, num_blocks);
    assert_eq!(prf_rerand.blocks.len() as u64, num_blocks);

    let decrypted = check_signed_value_and_re_rand_are_ok(
        &prf_not_rerand,
        &prf_rerand,
        cks,
        random_block_count as usize,
    );

    assert!(
        random_value_range.contains(&decrypted),
        "range: {random_value_range:?}, decrypted: {decrypted}"
    );
}

/// Generic PRF + re-randomization test
///
/// For each supported generation primitive it generates the PRF output with and without
/// re-randomization from the same seed and checks that:
/// - the random blocks differ (re-randomization changed ciphertexts)
/// - the expected trivial padding blocks are there
/// - both decrypt to the same value within the expected range
pub(crate) fn pseudo_random_integer_and_rerand_test<P, E>(param: P, mut test_runner: E)
where
    P: Into<TestParameters>,
    E: OprfReRandTestRunner,
{
    let mut rng = rand::thread_rng();

    let cks = test_runner.setup(param.into());

    // One seed for the test, do not use this in production, re-using a seed is bad
    let prf_seed: [u8; 256 / 8] = core::array::from_fn(|_| rng.gen());
    println!("prf_seed={prf_seed:?}");
    let prf_seed = prf_seed.as_slice();

    for rerand_hash_algo in [
        ReRandomizationHashAlgo::Blake3,
        ReRandomizationHashAlgo::Shake256,
    ] {
        println!("rerand_hash_algo: {rerand_hash_algo:?}");
        let seed_hasher = ReRandomizationSeedHasher::new(
            rerand_hash_algo,
            crate::shortint::oprf::TFHE_PRF_RERAND_DOMAIN_SEPARATOR,
        );
        let prf_rerand_context = PrfReRandomizationContext::new_with_hasher(
            crate::shortint::public_key::compact::TFHE_PKE_DOMAIN_SEPARATOR,
            seed_hasher,
        );

        subtest_integer_bounded_padding_stays_trivial(
            prf_seed,
            &cks,
            &mut test_runner,
            &prf_rerand_context,
        );

        // A fresh seed per call: re-using a seed across re-randomization calls is unsafe in
        // production, but each call here is self-contained (plain vs rerand from the same seed).
        subtest_unsigned_integer_full(prf_seed, &cks, &mut test_runner, &prf_rerand_context);
        subtest_signed_integer_full(prf_seed, &cks, &mut test_runner, &prf_rerand_context);

        // Run bounded tests a little more since they have a random component
        for _ in 0..10 {
            subtest_unsigned_integer_bounded(prf_seed, &cks, &mut test_runner, &prf_rerand_context);
            subtest_signed_integer_bounded(prf_seed, &cks, &mut test_runner, &prf_rerand_context);
        }

        // This test has a random component but is much heavier (and is skipped on backends that
        // do not support the re-randomizing custom-range primitive yet, e.g. GPU).
        for _ in 0..3 {
            subtest_unsigned_integer_custom_range(
                prf_seed,
                &cks,
                &mut test_runner,
                &prf_rerand_context,
            );
        }
    }
}

fn pseudo_random_integer_and_rerand<P>(param: P)
where
    P: Into<TestParameters>,
{
    pseudo_random_integer_and_rerand_test(param, CpuOprfReRandTestRunner::new());
}

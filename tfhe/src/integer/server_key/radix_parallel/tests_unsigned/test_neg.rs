use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix::neg::NegatedDegreeIter;
use crate::integer::server_key::radix_parallel::test_harness::{
    radix_edges_fixed_cases, ExecuteOn, TestBuilder, TestContext,
};
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{FunctionExecutor, NB_CTXT};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, panic_if_any_block_info_exceeds_max_degree_or_noise,
    panic_if_any_block_values_exceeds_its_degree, unsigned_modulus, CpuFunctionExecutor,
    ExpectedDegrees, ExpectedNoiseLevels,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::tests::uint::Uint;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
use crate::shortint::ciphertext::MaxDegree;
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_default_neg);
create_parameterized_test!(integer_default_overflowing_neg);
create_parameterized_test!(integer_is_neg_possible);

fn integer_default_neg<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::neg_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_neg_test(&ctx, executor);
}

fn integer_default_overflowing_neg<P>(param: P)
where
    P: Into<TestParameters>,
{
    let ctx = TestContext::from_env(param);
    let mut executor = CpuFunctionExecutor::new(&ServerKey::overflowing_neg_parallelized);
    executor.setup_with_server_key(ctx.server_key());
    default_overflowing_neg_test(&ctx, executor);
}

impl ExpectedDegrees {
    fn after_unchecked_neg(&mut self, lhs: &RadixCiphertext) -> &Self {
        self.set_with(NegatedDegreeIter::new(
            lhs.blocks
                .iter()
                .map(|block| (block.degree, block.message_modulus)),
        ));
        self
    }
}

//=============================================================================
// Unchecked Tests
//=============================================================================

pub(crate) fn unchecked_neg_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    let max_noise_level = sks.key.max_noise_level;
    let max_degree = sks.key.max_degree;

    let trivial0 = sks.create_trivial_radix(0u64, NB_CTXT);
    executor.setup(&cks, sks);

    // negation involves either scalar operation or pbs, noise is always nominal
    let expected_noise_levels = ExpectedNoiseLevels::new(NoiseLevel::NOMINAL, NB_CTXT);
    let mut expected_degrees = ExpectedDegrees::new(Degree::new(0), NB_CTXT);

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;

        let ctxt = cks.encrypt(clear);

        let encrypted_result = executor.execute(&ctxt);

        expected_noise_levels.panic_if_any_is_not_equal(&encrypted_result);
        expected_degrees
            .after_unchecked_neg(&ctxt)
            .panic_if_any_is_not_equal(&encrypted_result);
        panic_if_any_block_values_exceeds_its_degree(&encrypted_result, &cks);
        panic_if_any_block_info_exceeds_max_degree_or_noise(
            &encrypted_result,
            max_degree,
            max_noise_level,
        );

        let decrypted_result: u64 = cks.decrypt(&encrypted_result);
        let expected_result = clear.wrapping_neg() % modulus;
        assert_eq!(decrypted_result, expected_result);
    }

    // negation of trivial 0
    {
        let ct_res = executor.execute(&trivial0);
        let dec_res: u64 = cks.decrypt(&ct_res);
        assert_eq!(0, dec_res);
    }
}

//=============================================================================
// Default Tests
//=============================================================================

pub(crate) fn default_neg_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext,), RadixCiphertext>,
{
    TestBuilder::new(ctx)
        .n_random(4)
        .fixed_cases(radix_edges_fixed_cases::<Uint>)
        .execute(executor, |(value,): (Uint,)| value.wrapping_neg());
}

pub(crate) fn default_overflowing_neg_test<E>(ctx: &TestContext, executor: E)
where
    E: ExecuteOn<(RadixCiphertext,), (RadixCiphertext, BooleanBlock)>,
{
    TestBuilder::new(ctx)
        .n_random(4)
        .fixed_cases(radix_edges_fixed_cases::<Uint>)
        .execute(executor, |(value,): (Uint,)| value.overflowing_neg());
}

//=============================================================================
// is_neg_possible
//=============================================================================

fn integer_is_neg_possible<P>(param: P)
where
    P: Into<TestParameters>,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let message_modulus = cks.parameters().message_modulus();
    let carry_modulus = cks.parameters().carry_modulus();
    // The degree a block can hold without touching the padding bit.
    let max_degree = MaxDegree::from_msg_carry_modulus(message_modulus, carry_modulus);
    let max_noise_level = sks.key.max_noise_level;
    let modulus = unsigned_modulus(message_modulus, NB_CTXT as u32);

    // We are using trivial ciphertexts as their degrees is tighter than true encrypted values.
    // i.e their degrees is the exact value stored
    for clear in [1u64, 2, message_modulus.0 - 1, modulus - 1] {
        let ctxt = sks.create_trivial_radix(clear, NB_CTXT);
        sks.is_neg_possible(&ctxt)
            .expect("It must be possible to negate this value");

        let encrypted_result = sks.unchecked_neg(&ctxt);
        let decrypted_result: u64 = cks.decrypt(&encrypted_result);
        assert_eq!(decrypted_result, clear.wrapping_neg() % modulus);
    }

    // An input the negation cannot handle
    {
        let degrees = [1, message_modulus.0, max_degree.get()];
        let ctxt = trivial_radix_with_degrees(&sks, &degrees, degrees.len());
        sks.is_neg_possible(&ctxt).expect_err(&format!(
            "negating blocks with degrees {degrees:?} overflows, it must not be accepted"
        ));
    }

    // Whenever the negation is accepted, doing it must leave every block within what
    // it can hold.
    let mut rng = rand::thread_rng();
    let notable_degrees = [
        0,
        1,
        message_modulus.0 - 1,
        message_modulus.0,
        max_degree.get(),
    ];
    for _ in 0..nb_tests {
        let degrees = (0..NB_CTXT)
            .map(|_| {
                if rng.gen_bool(0.5) {
                    notable_degrees[rng.gen_range(0..notable_degrees.len())]
                } else {
                    rng.gen_range(0..=max_degree.get())
                }
            })
            .collect::<Vec<_>>();

        let ctxt = trivial_radix_with_degrees(&sks, &degrees, NB_CTXT);
        if sks.is_neg_possible(&ctxt).is_err() {
            continue;
        }

        let encrypted_result = sks.unchecked_neg(&ctxt);
        panic_if_any_block_info_exceeds_max_degree_or_noise(
            &encrypted_result,
            max_degree,
            max_noise_level,
        );
        panic_if_any_block_values_exceeds_its_degree(&encrypted_result, &cks);
    }

    // `neg_parallelized` cleans its input, so it must return the right value even for block
    // degrees the unchecked negation cannot handle, i.e. the ones `is_neg_possible` rejects.
    //
    // neg_parallelized should not return an output that has its padding bit set
    {
        let degrees = [
            message_modulus.0 - 1,
            message_modulus.0,
            max_degree.get(),
            message_modulus.0 - 1,
        ];
        let values = [1, 1, 0, 1];
        let ctxt = radix_with_degrees_and_values(&cks, &degrees, &values);
        assert!(
            !ctxt.block_carries_are_empty(),
            "the input must have carries, so that it goes through the cleaning preamble"
        );

        assert!(
            sks.is_neg_possible(&ctxt).is_err(),
            "negating blocks with degrees {degrees:?} overflows, it must not be accepted"
        );

        let cks: &crate::integer::ClientKey = cks.as_ref();
        let modulus = unsigned_modulus(message_modulus, degrees.len() as u32);
        let clear: u64 = cks.decrypt_radix(&ctxt);

        let encrypted_result = sks.neg_parallelized(&ctxt);
        let decrypted_result: u64 = cks.decrypt_radix(&encrypted_result);
        assert_eq!(
            decrypted_result,
            clear.wrapping_neg() % modulus,
            "neg_parallelized returned a wrong value for a ciphertext with degrees {degrees:?}"
        );
    }
}

/// Builds a radix whose block at index `i` encrypts `values[i]` but carries a degree of
/// `degrees[i]`.
fn radix_with_degrees_and_values(
    cks: &RadixClientKey,
    degrees: &[u64],
    values: &[u64],
) -> RadixCiphertext {
    let blocks = degrees
        .iter()
        .zip(values)
        .map(|(&degree, &value)| {
            assert!(
                value <= degree,
                "a block cannot hold a value above its degree"
            );
            let mut block = cks.as_ref().key.encrypt(value);
            block.degree = Degree::new(degree);
            block
        })
        .collect::<Vec<_>>();
    RadixCiphertext::from(blocks)
}

/// Builds a radix of `num_blocks` trivial blocks, where the block at index `i` has a value, and
/// so a degree, of `degrees[i]`. Blocks past `degrees` are trivial zeros.
fn trivial_radix_with_degrees(
    sks: &ServerKey,
    degrees: &[u64],
    num_blocks: usize,
) -> RadixCiphertext {
    let blocks = (0..num_blocks)
        .map(|i| {
            let mut block = sks.key.create_trivial(0);
            if let Some(&degree) = degrees.get(i) {
                sks.key
                    .unchecked_scalar_add_assign(&mut block, u8::try_from(degree).unwrap());
            }
            assert_eq!(block.degree.get(), degrees.get(i).copied().unwrap_or(0));
            block
        })
        .collect::<Vec<_>>();
    RadixCiphertext::from(blocks)
}

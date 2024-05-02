mod modulus_switch_compression;
pub(crate) mod test_add;
pub(crate) mod test_bitwise_op;
pub(crate) mod test_cmux;
pub(crate) mod test_comparison;
pub(crate) mod test_mul;
pub(crate) mod test_neg;
pub(crate) mod test_rotate;
pub(crate) mod test_scalar_add;
pub(crate) mod test_scalar_bitwise_op;
pub(crate) mod test_scalar_comparison;
pub(crate) mod test_scalar_mul;
pub(crate) mod test_scalar_rotate;
pub(crate) mod test_scalar_shift;
pub(crate) mod test_scalar_sub;
pub(crate) mod test_shift;
pub(crate) mod test_sub;
pub(crate) mod test_vector_comparisons;

use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    CpuFunctionExecutor, NB_CTXT, NB_TESTS, NB_TESTS_SMALLER, NB_TESTS_UNCHECKED,
};
use crate::integer::tests::create_parametrized_test;
use crate::integer::{
    BooleanBlock, IntegerKeyKind, RadixClientKey, ServerKey, SignedRadixCiphertext,
};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;
use itertools::{iproduct, izip};
use rand::prelude::ThreadRng;
use rand::Rng;
use std::sync::Arc;

impl<'a, F> FunctionExecutor<&'a SignedRadixCiphertext, (SignedRadixCiphertext, BooleanBlock)>
    for CpuFunctionExecutor<F>
where
    F: Fn(&ServerKey, &SignedRadixCiphertext) -> (SignedRadixCiphertext, BooleanBlock),
{
    fn setup(&mut self, _cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.sks = Some(sks);
    }

    fn execute(
        &mut self,
        input: &'a SignedRadixCiphertext,
    ) -> (SignedRadixCiphertext, BooleanBlock) {
        let sks = self.sks.as_ref().expect("setup was not properly called");
        (self.func)(sks, input)
    }
}

impl<'a, F> FunctionExecutor<&'a SignedRadixCiphertext, SignedRadixCiphertext>
    for CpuFunctionExecutor<F>
where
    F: Fn(&ServerKey, &SignedRadixCiphertext) -> SignedRadixCiphertext,
{
    fn setup(&mut self, _cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.sks = Some(sks);
    }

    fn execute(&mut self, input: &'a SignedRadixCiphertext) -> SignedRadixCiphertext {
        let sks = self.sks.as_ref().expect("setup was not properly called");
        (self.func)(sks, input)
    }
}
impl<'a, F> FunctionExecutor<&'a mut SignedRadixCiphertext, ()> for CpuFunctionExecutor<F>
where
    F: Fn(&ServerKey, &'a mut SignedRadixCiphertext),
{
    fn setup(&mut self, _cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.sks = Some(sks);
    }

    fn execute(&mut self, input: &'a mut SignedRadixCiphertext) {
        let sks = self.sks.as_ref().expect("setup was not properly called");
        (self.func)(sks, input);
    }
}

impl<'a, F> FunctionExecutor<&'a mut SignedRadixCiphertext, SignedRadixCiphertext>
    for CpuFunctionExecutor<F>
where
    F: Fn(&ServerKey, &mut SignedRadixCiphertext) -> SignedRadixCiphertext,
{
    fn setup(&mut self, _cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.sks = Some(sks);
    }

    fn execute(&mut self, input: &'a mut SignedRadixCiphertext) -> SignedRadixCiphertext {
        let sks = self.sks.as_ref().expect("setup was not properly called");
        (self.func)(sks, input)
    }
}

//================================================================================
//     Encrypt/Decrypt Tests
//================================================================================

create_parametrized_test!(integer_signed_encrypt_decrypt);
create_parametrized_test!(integer_signed_encrypt_decrypt_128_bits);

fn integer_signed_encrypt_decrypt_128_bits(param: impl Into<PBSParameters>) {
    let (cks, _) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();
    let num_block =
        (128f64 / (cks.parameters().message_modulus().0 as f64).log(2.0)).ceil() as usize;

    for _ in 0..NB_TESTS {
        let clear = rng.gen::<i128>();

        let ct = cks.encrypt_signed_radix(clear, num_block);

        let dec: i128 = cks.decrypt_signed_radix(&ct);
        assert_eq!(clear, dec);
    }
}

fn integer_signed_encrypt_decrypt(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    for _ in 0..NB_TESTS {
        let clear = rng.gen_range(i64::MIN..=0) % modulus;

        let ct = cks.encrypt_signed_radix(clear, NB_CTXT);
        let dec: i64 = cks.decrypt_signed_radix(&ct);
        assert_eq!(clear, dec);

        let trivial_ct = sks.create_trivial_radix(clear, NB_CTXT);
        let dec: i64 = cks.decrypt_signed_radix(&trivial_ct);
        assert_eq!(clear, dec);
    }

    for _ in 0..NB_TESTS {
        let clear = rng.gen_range(0..=i64::MAX) % modulus;

        let ct = cks.encrypt_signed_radix(clear, NB_CTXT);
        let dec: i64 = cks.decrypt_signed_radix(&ct);
        assert_eq!(clear, dec);

        let trivial_ct = sks.create_trivial_radix(clear, NB_CTXT);
        let dec: i64 = cks.decrypt_signed_radix(&trivial_ct);
        assert_eq!(clear, dec);
    }
}

//================================================================================
//     Unchecked Tests
//================================================================================

create_parametrized_test!(
    integer_signed_unchecked_div_rem {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Does not support 1_1
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);
create_parametrized_test!(
    integer_signed_unchecked_div_rem_floor {
        coverage => {
            COVERAGE_PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            COVERAGE_PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
        },
        no_coverage => {
            // Does not support 1_1
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
        }
    }
);
create_parametrized_test!(integer_signed_unchecked_absolute_value);

fn integer_signed_unchecked_absolute_value(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    // For signed integers, the range of value is [-modulus..modulus[
    // e.g.: for i8, the range is [-128..128[ <=> [-128..127]
    // which means -modulus cannot be represented.
    //
    // In Rust, .abs() / .wrapping_abs() returns MIN (-modulus)
    // https://doc.rust-lang.org/std/primitive.i8.html#method.wrapping_abs
    //
    // Here we test we have same behaviour
    //
    // (Conveniently, when using Two's complement, casting the result of abs to
    // an unsigned to will give correct value for -modulus
    // e.g.:(-128i8).wrapping_abs() as u8 == 128
    {
        let clear_0 = -modulus;
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ct_res = sks.unchecked_abs_parallelized(&ctxt_0);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        assert_eq!(dec_res, -modulus);
    }

    for _ in 0..NB_TESTS {
        let clear_0 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let ct_res = sks.unchecked_abs_parallelized(&ctxt_0);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = absolute_value_under_modulus(clear_0, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

fn integer_signed_unchecked_div_rem(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    // Test case of division by 0
    // This is mainly to show we know the behaviour of division by 0
    // using the current algorithm
    for clear_0 in [0i64, rng.gen::<i64>() % modulus] {
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ctxt_1 = cks.encrypt_signed_radix(0, NB_CTXT);

        let (q_res, r_res) = sks.unchecked_div_rem_parallelized(&ctxt_0, &ctxt_1);
        let q: i64 = cks.decrypt_signed_radix(&q_res);
        let r: i64 = cks.decrypt_signed_radix(&r_res);

        assert_eq!(r, clear_0);
        assert_eq!(q, if clear_0 >= 0 { -1 } else { 1 });
    }

    // Div is the slowest operation
    for _ in 0..NB_TESTS_SMALLER {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = loop {
            let value = rng.gen::<i64>() % modulus;
            if value != 0 {
                break value;
            }
        };

        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);

        let (q_res, r_res) = sks.unchecked_div_rem_parallelized(&ctxt_0, &ctxt_1);
        let q: i64 = cks.decrypt_signed_radix(&q_res);
        let r: i64 = cks.decrypt_signed_radix(&r_res);
        let expected_q = signed_div_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(
            q, expected_q,
            "Invalid division result, for {clear_0} / {clear_1} \
            expected quotient: {expected_q} got: {q}"
        );
        let expected_r = signed_rem_under_modulus(clear_0, clear_1, modulus);
        assert_eq!(
            r, expected_r,
            "Invalid remainder result, for {clear_0} % {clear_1} \
            expected quotient: {expected_r} got: {r}"
        );
    }
}

fn integer_signed_unchecked_div_rem_floor(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    if modulus > 8 {
        // Some hard coded test for flooring div
        // For example, truncating_div(-7, 3) would give q = -2 and r = -1
        // truncating div is the default in rust (and many other languages)
        // Python does use a flooring div, so you can try these values in you local
        // interpreter.
        let values = [
            (-8, 3, -3, 1),
            (8, -3, -3, -1),
            (7, 3, 2, 1),
            (-7, 3, -3, 2),
            (7, -3, -3, -2),
            (-7, -3, 2, -1),
        ];
        for (clear_0, clear_1, expected_q, expected_r) in values {
            let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
            let ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);

            let (q_res, r_res) = sks.unchecked_div_rem_floor_parallelized(&ctxt_0, &ctxt_1);
            let q: i64 = cks.decrypt_signed_radix(&q_res);
            let r: i64 = cks.decrypt_signed_radix(&r_res);

            // Uses the hardcoded values to also test our clear function
            let (q2, r2) = signed_div_rem_floor_under_modulus(clear_0, clear_1, modulus);

            assert_eq!(q2, expected_q);
            assert_eq!(r2, expected_r);
            assert_eq!(q, expected_q);
            assert_eq!(r, expected_r);
        }
    }

    // A test where the division is whole, aka remainder is zero
    {
        let ctxt_0 = cks.encrypt_signed_radix(4, NB_CTXT);
        let ctxt_1 = cks.encrypt_signed_radix(-2, NB_CTXT);

        let (q_res, r_res) = sks.unchecked_div_rem_floor_parallelized(&ctxt_0, &ctxt_1);
        let q: i64 = cks.decrypt_signed_radix(&q_res);
        let r: i64 = cks.decrypt_signed_radix(&r_res);

        // Uses the hardcoded values to also test our clear function
        let (q2, r2) = signed_div_rem_floor_under_modulus(4, -2, modulus);

        assert_eq!(q2, -2);
        assert_eq!(r2, 0);
        assert_eq!(q, -2);
        assert_eq!(r, 0);
    }

    // Div is the slowest operation
    for _ in 0..5 {
        let clear_0 = rng.gen::<i64>() % modulus;
        let clear_1 = loop {
            let value = rng.gen::<i64>() % modulus;
            if value != 0 {
                break value;
            }
        };

        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ctxt_1 = cks.encrypt_signed_radix(clear_1, NB_CTXT);

        let (q_res, r_res) = sks.unchecked_div_rem_floor_parallelized(&ctxt_0, &ctxt_1);
        let q: i64 = cks.decrypt_signed_radix(&q_res);
        let r: i64 = cks.decrypt_signed_radix(&r_res);
        let (expected_q, expected_r) =
            signed_div_rem_floor_under_modulus(clear_0, clear_1, modulus);

        println!("{clear_0} / {clear_1} -> ({q}, {r})");
        assert_eq!(q, expected_q);
        assert_eq!(r, expected_r);
    }
}

//================================================================================
//     Smart Tests
//================================================================================

create_parametrized_test!(integer_signed_smart_absolute_value);

fn integer_signed_smart_absolute_value(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    {
        let clear_0 = -modulus;
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ct_res = sks.abs_parallelized(&ctxt_0);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        assert_eq!(dec_res, -modulus);
    }

    for _ in 0..NB_TESTS {
        let mut clear_0 = rng.gen::<i64>() % modulus;
        let clear_to_add = rng.gen::<i64>() % modulus;

        let mut ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_to_add);
        clear_0 = signed_add_under_modulus(clear_0, clear_to_add, modulus);

        let ct_res = sks.abs_parallelized(&ctxt_0);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = absolute_value_under_modulus(clear_0, modulus);
        assert_eq!(clear_res, dec_res);
    }
}

//================================================================================
//     Default Tests
//================================================================================

create_parametrized_test!(integer_signed_default_absolute_value);

create_parametrized_test!(integer_signed_default_trailing_zeros);
create_parametrized_test!(integer_signed_default_trailing_ones);
create_parametrized_test!(integer_signed_default_leading_zeros);
create_parametrized_test!(integer_signed_default_leading_ones);
create_parametrized_test!(integer_signed_default_ilog2);
create_parametrized_test!(integer_signed_default_checked_ilog2 {
    // uses comparison so 1_1 parameters are not supported
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});

fn integer_signed_default_absolute_value(param: impl Into<PBSParameters>) {
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    {
        let clear_0 = -modulus;
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        let ct_res = sks.abs_parallelized(&ctxt_0);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        assert_eq!(dec_res, -modulus);
    }

    for _ in 0..NB_TESTS_SMALLER {
        let mut clear_0 = rng.gen::<i64>() % modulus;
        let clear_to_add = rng.gen::<i64>() % modulus;

        let mut ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);
        sks.unchecked_scalar_add_assign(&mut ctxt_0, clear_to_add);
        clear_0 = signed_add_under_modulus(clear_0, clear_to_add, modulus);

        let ct_res = sks.abs_parallelized(&ctxt_0);
        let dec_res: i64 = cks.decrypt_signed_radix(&ct_res);
        let clear_res = absolute_value_under_modulus(clear_0, modulus);
        assert_eq!(clear_res, dec_res);

        let ct_res2 = sks.abs_parallelized(&ctxt_0);
        assert_eq!(ct_res2, ct_res);
    }
}

fn integer_signed_default_trailing_zeros<P>(param: P)
where
    P: Into<PBSParameters>,
{
    crate::integer::server_key::radix_parallel::ilog2::tests_signed::default_trailing_zeros_test(
        param,
    );
}

fn integer_signed_default_trailing_ones<P>(param: P)
where
    P: Into<PBSParameters>,
{
    crate::integer::server_key::radix_parallel::ilog2::tests_signed::default_trailing_ones_test(
        param,
    );
}

fn integer_signed_default_leading_zeros<P>(param: P)
where
    P: Into<PBSParameters>,
{
    crate::integer::server_key::radix_parallel::ilog2::tests_signed::default_leading_zeros_test(
        param,
    );
}

fn integer_signed_default_leading_ones<P>(param: P)
where
    P: Into<PBSParameters>,
{
    crate::integer::server_key::radix_parallel::ilog2::tests_signed::default_leading_ones_test(
        param,
    );
}

fn integer_signed_default_ilog2<P>(param: P)
where
    P: Into<PBSParameters>,
{
    crate::integer::server_key::radix_parallel::ilog2::tests_signed::default_ilog2_test(param);
}

fn integer_signed_default_checked_ilog2<P>(param: P)
where
    P: Into<PBSParameters>,
{
    crate::integer::server_key::radix_parallel::ilog2::tests_signed::default_checked_ilog2_test(
        param,
    );
}

//================================================================================
//     Unchecked Scalar Tests
//================================================================================
create_parametrized_test!(integer_signed_unchecked_scalar_div_rem);
create_parametrized_test!(integer_signed_unchecked_scalar_div_rem_floor);

fn integer_signed_unchecked_scalar_div_rem(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    {
        let clear_0 = rng.gen::<i64>() % modulus;
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let result = std::panic::catch_unwind(|| {
            let _ = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, 0);
        });
        assert!(result.is_err(), "Division by zero did not panic");
    }

    // check when scalar is out of ciphertext MIN..=MAX
    for d in [
        rng.gen_range(i64::MIN..-modulus),
        rng.gen_range(modulus..=i64::MAX),
    ] {
        for numerator in [rng.gen_range(-modulus..=0), rng.gen_range(0..modulus)] {
            let ctxt_0 = cks.encrypt_signed_radix(numerator, NB_CTXT);

            let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, d);
            let q: i64 = cks.decrypt_signed_radix(&q_res);
            let r: i64 = cks.decrypt_signed_radix(&r_res);
            assert_eq!(q, signed_div_under_modulus(numerator, d, modulus));
            assert_eq!(r, signed_rem_under_modulus(numerator, d, modulus));
        }
    }

    // The algorithm has a special case for when divisor is 1 or -1
    for d in [1i64, -1i64] {
        let clear_0 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, d);
        let q: i64 = cks.decrypt_signed_radix(&q_res);
        let r: i64 = cks.decrypt_signed_radix(&r_res);
        assert_eq!(q, signed_div_under_modulus(clear_0, d, modulus));
        assert_eq!(r, signed_rem_under_modulus(clear_0, d, modulus));
    }

    // 3 / -3 takes the second branch in the if else if series
    for d in [3, -3] {
        {
            let neg_clear_0 = rng.gen_range(-modulus..=0);
            let ctxt_0 = cks.encrypt_signed_radix(neg_clear_0, NB_CTXT);
            println!("{neg_clear_0} / {d}");
            let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, d);
            let q: i64 = cks.decrypt_signed_radix(&q_res);
            let r: i64 = cks.decrypt_signed_radix(&r_res);
            assert_eq!(q, signed_div_under_modulus(neg_clear_0, d, modulus));
            assert_eq!(r, signed_rem_under_modulus(neg_clear_0, d, modulus));
        }

        {
            let pos_clear_0 = rng.gen_range(0..modulus);
            let ctxt_0 = cks.encrypt_signed_radix(pos_clear_0, NB_CTXT);
            println!("{pos_clear_0} / {d}");
            let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, d);
            let q: i64 = cks.decrypt_signed_radix(&q_res);
            let r: i64 = cks.decrypt_signed_radix(&r_res);
            assert_eq!(q, signed_div_under_modulus(pos_clear_0, d, modulus));
            assert_eq!(r, signed_rem_under_modulus(pos_clear_0, d, modulus));
        }
    }

    // Param 1_1 cannot do this, with our NB_CTXT
    if modulus >= 43 {
        // For param_2_2 this will take the third branch in the if else if series
        for d in [-89, 89] {
            {
                let neg_clear_0 = rng.gen_range(-modulus..=0);
                let ctxt_0 = cks.encrypt_signed_radix(neg_clear_0, NB_CTXT);
                let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, d);
                let q: i64 = cks.decrypt_signed_radix(&q_res);
                let r: i64 = cks.decrypt_signed_radix(&r_res);
                assert_eq!(q, signed_div_under_modulus(neg_clear_0, d, modulus));
                assert_eq!(r, signed_rem_under_modulus(neg_clear_0, d, modulus));
            }

            {
                let pos_clear_0 = rng.gen_range(0..modulus);
                let ctxt_0 = cks.encrypt_signed_radix(pos_clear_0, NB_CTXT);
                println!("{pos_clear_0} / {d}");
                let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, d);
                let q: i64 = cks.decrypt_signed_radix(&q_res);
                let r: i64 = cks.decrypt_signed_radix(&r_res);
                assert_eq!(q, signed_div_under_modulus(pos_clear_0, d, modulus));
                assert_eq!(r, signed_rem_under_modulus(pos_clear_0, d, modulus));
            }
        }

        // For param_2_2 this will take the first branch
        for (clear_0, clear_1) in [(43, 8), (43, -8), (-43, 8), (-43, -8)] {
            let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

            let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, clear_1);
            let q: i64 = cks.decrypt_signed_radix(&q_res);
            let r: i64 = cks.decrypt_signed_radix(&r_res);
            assert_eq!(q, signed_div_under_modulus(clear_0, clear_1, modulus));
            assert_eq!(r, signed_rem_under_modulus(clear_0, clear_1, modulus));
        }
    }

    for d in [-modulus, modulus - 1] {
        {
            let neg_clear_0 = rng.gen_range(-modulus..=0);
            let ctxt_0 = cks.encrypt_signed_radix(neg_clear_0, NB_CTXT);
            let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, d);
            let q: i64 = cks.decrypt_signed_radix(&q_res);
            let r: i64 = cks.decrypt_signed_radix(&r_res);
            assert_eq!(q, signed_div_under_modulus(neg_clear_0, d, modulus));
            assert_eq!(r, signed_rem_under_modulus(neg_clear_0, d, modulus));
        }

        {
            let pos_clear_0 = rng.gen_range(0..modulus);
            let ctxt_0 = cks.encrypt_signed_radix(pos_clear_0, NB_CTXT);
            let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, d);
            let q: i64 = cks.decrypt_signed_radix(&q_res);
            let r: i64 = cks.decrypt_signed_radix(&r_res);
            assert_eq!(q, signed_div_under_modulus(pos_clear_0, d, modulus));
            assert_eq!(r, signed_rem_under_modulus(pos_clear_0, d, modulus));
        }
    }

    let lhs_values = random_signed_value_under_modulus::<6>(&mut rng, modulus);
    let rhs_values = random_non_zero_signed_value_under_modulus::<6>(&mut rng, modulus);

    for (clear_lhs, clear_rhs) in iproduct!(lhs_values, rhs_values) {
        let ctxt_0 = cks.encrypt_signed_radix(clear_lhs, NB_CTXT);

        let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_parallelized(&ctxt_0, clear_rhs);
        let q: i64 = cks.decrypt_signed_radix(&q_res);
        let r: i64 = cks.decrypt_signed_radix(&r_res);
        assert_eq!(q, signed_div_under_modulus(clear_lhs, clear_rhs, modulus));
        assert_eq!(r, signed_rem_under_modulus(clear_lhs, clear_rhs, modulus));
    }
}

fn integer_signed_unchecked_scalar_div_rem_floor(param: impl Into<PBSParameters>) {
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    if modulus > 8 {
        // Some hard coded test for flooring div
        // For example, truncating_div(-7, 3) would give q = -2 and r = -1
        // truncating div is the default in rust (and many other languages)
        // Python does use a flooring div, so you can try these values in you local
        // interpreter.
        let values = [
            (-8, 3, -3, 1),
            (8, -3, -3, -1),
            (7, 3, 2, 1),
            (-7, 3, -3, 2),
            (7, -3, -3, -2),
            (-7, -3, 2, -1),
        ];
        for (clear_0, clear_1, expected_q, expected_r) in values {
            let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

            let (q_res, r_res) =
                sks.unchecked_signed_scalar_div_rem_floor_parallelized(&ctxt_0, clear_1);
            let q: i64 = cks.decrypt_signed_radix(&q_res);
            let r: i64 = cks.decrypt_signed_radix(&r_res);

            // Also serves as a test for our function

            let (q2, r2) = signed_div_rem_floor_under_modulus(clear_0, clear_1, modulus);

            assert_eq!(q2, expected_q);
            assert_eq!(r2, expected_r);
            assert_eq!(q, expected_q);
            assert_eq!(r, expected_r);
        }
    }

    {
        let clear_0 = rng.gen::<i64>() % modulus;
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let result = std::panic::catch_unwind(|| {
            let _ = sks.unchecked_signed_scalar_div_rem_floor_parallelized(&ctxt_0, 0);
        });
        assert!(result.is_err(), "Division by zero did not panic");
    }

    // check when scalar is out of ciphertext MIN..=MAX
    for d in [
        rng.gen_range(i64::MIN..-modulus),
        rng.gen_range(modulus..=i64::MAX),
    ] {
        for numerator in [0, rng.gen_range(-modulus..=0), rng.gen_range(0..modulus)] {
            let ctxt_0 = cks.encrypt_signed_radix(numerator, NB_CTXT);

            let (q_res, r_res) = sks.unchecked_signed_scalar_div_rem_floor_parallelized(&ctxt_0, d);
            let q: i64 = cks.decrypt_signed_radix(&q_res);
            let r: i64 = cks.decrypt_signed_radix(&r_res);

            println!("{numerator} + {d} -> ({q}, {r})");

            let mut expected_q = numerator / d;
            let mut expected_r = numerator % d;
            assert_eq!(expected_q, 0);
            assert_eq!(expected_r, numerator);

            // This does the almost the same thing as signed_div_mod_under_modulus
            // but it applies a bit mask where the tested function also does
            if expected_r != 0 && ((expected_r < 0) != (d < 0)) {
                expected_q = -1;
                // numerator = (quotient * divisor) + rest
                expected_r = signed_sub_under_modulus(
                    numerator,
                    signed_mul_under_modulus(expected_q, d & ((2 * modulus) - 1), modulus),
                    modulus,
                );
            }

            assert_eq!(q, expected_q);
            assert_eq!(r, expected_r);
        }
    }

    let lhs_values = random_signed_value_under_modulus::<5>(&mut rng, modulus);
    let rhs_values = random_non_zero_signed_value_under_modulus::<5>(&mut rng, modulus);

    for (clear_lhs, clear_rhs) in iproduct!(lhs_values, rhs_values) {
        let ctxt_0 = cks.encrypt_signed_radix(clear_lhs, NB_CTXT);

        let (q_res, r_res) =
            sks.unchecked_signed_scalar_div_rem_floor_parallelized(&ctxt_0, clear_rhs);
        let q: i64 = cks.decrypt_signed_radix(&q_res);
        let r: i64 = cks.decrypt_signed_radix(&r_res);
        let (expected_q, expected_r) =
            signed_div_rem_floor_under_modulus(clear_lhs, clear_rhs, modulus);
        assert_eq!(q, expected_q);
        assert_eq!(r, expected_r);
    }
}

//================================================================================
//     Smart Scalar Tests
//================================================================================

//================================================================================
//     Default Scalar Tests
//================================================================================

create_parametrized_test!(integer_signed_default_scalar_div_rem);

fn integer_signed_default_scalar_div_rem(param: impl Into<PBSParameters>) {
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    sks.set_deterministic_pbs_execution(true);

    let mut rng = rand::thread_rng();

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    {
        let clear_0 = rng.gen::<i64>() % modulus;
        let ctxt_0 = cks.encrypt_signed_radix(clear_0, NB_CTXT);

        let result = std::panic::catch_unwind(|| {
            let _ = sks.signed_scalar_div_rem_parallelized(&ctxt_0, 0);
        });
        assert!(result.is_err(), "Division by zero did not panic");
    }

    let lhs_values = random_signed_value_under_modulus::<5>(&mut rng, modulus);
    let rhs_values = random_non_zero_signed_value_under_modulus::<5>(&mut rng, modulus);

    for (mut clear_lhs, clear_rhs) in iproduct!(lhs_values, rhs_values) {
        let mut ctxt_0 = cks.encrypt_signed_radix(clear_lhs, NB_CTXT);

        // Make the degree non-fresh
        let offset = random_non_zero_value(&mut rng, modulus);
        sks.unchecked_scalar_add_assign(&mut ctxt_0, offset);
        clear_lhs = signed_add_under_modulus(clear_lhs, offset, modulus);
        assert!(!ctxt_0.block_carries_are_empty());

        let (q_res, r_res) = sks.signed_scalar_div_rem_parallelized(&ctxt_0, clear_rhs);
        let q: i64 = cks.decrypt_signed_radix(&q_res);
        let r: i64 = cks.decrypt_signed_radix(&r_res);
        let expected_q = signed_div_under_modulus(clear_lhs, clear_rhs, modulus);
        let expected_r = signed_rem_under_modulus(clear_lhs, clear_rhs, modulus);
        assert_eq!(
            q, expected_q,
            "Invalid quotient result for division, for {clear_lhs} / {clear_rhs}, \
             Expected {expected_q}, got {q}"
        );
        assert_eq!(
            r, expected_r,
            "Invalid remainder result for division, for {clear_lhs} % {clear_rhs}, \
             Expected {expected_r}, got {r}"
        );

        let (q2_res, r2_res) = sks.signed_scalar_div_rem_parallelized(&ctxt_0, clear_rhs);
        assert_eq!(q2_res, q_res, "Failed determinism check");
        assert_eq!(r2_res, r_res, "Failed determinism check");
    }
}

//================================================================================
//     Helper functions
//================================================================================

pub(crate) fn signed_add_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> i64 {
    signed_overflowing_add_under_modulus(lhs, rhs, modulus).0
}

// Adds two signed number modulo the given modulus
//
// This is to 'simulate' i8, i16, ixy using i64 integers
//
// lhs and rhs must be in [-modulus..modulus[
pub(crate) fn signed_overflowing_add_under_modulus(
    lhs: i64,
    rhs: i64,
    modulus: i64,
) -> (i64, bool) {
    assert!(modulus > 0);
    assert!((-modulus..modulus).contains(&lhs));

    // The code below requires rhs and lhs to be in range -modulus..modulus
    // in scalar tests, rhs may exceed modulus
    // so we truncate it (is the fhe ops does)
    let (mut res, mut overflowed) = if (-modulus..modulus).contains(&rhs) {
        (lhs + rhs, false)
    } else {
        // 2*modulus to get all the bits
        (lhs + (rhs % (2 * modulus)), true)
    };

    if res < -modulus {
        // rem_euclid(modulus) would also work
        res = modulus + (res - -modulus);
        overflowed = true;
    } else if res > modulus - 1 {
        res = -modulus + (res - modulus);
        overflowed = true;
    }
    (res, overflowed)
}

pub(crate) fn signed_neg_under_modulus(lhs: i64, modulus: i64) -> i64 {
    assert!(modulus > 0);
    let mut res = -lhs;
    if res < -modulus {
        // rem_euclid(modulus) would also work
        res = modulus + (res - -modulus);
    } else if res > modulus - 1 {
        res = -modulus + (res - modulus);
    }
    res
}

// Subs two signed number modulo the given modulus
//
// This is to 'simulate' i8, i16, ixy using i64 integers
//
// lhs and rhs must be in [-modulus..modulus[
pub(crate) fn signed_sub_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> i64 {
    signed_overflowing_sub_under_modulus(lhs, rhs, modulus).0
}

pub(crate) fn signed_overflowing_sub_under_modulus(
    lhs: i64,
    rhs: i64,
    modulus: i64,
) -> (i64, bool) {
    // Technically we should be able to call overflowing_add_under_modulus(lhs, -rhs, ...)
    // but due to -rhs being a 'special case' when rhs == -modulus, we have to
    // so the impl here
    assert!(modulus > 0);
    assert!((-modulus..modulus).contains(&lhs));

    // The code below requires rhs and lhs to be in range -modulus..modulus
    // in scalar tests, rhs may exceed modulus
    // so we truncate it (is the fhe ops does)
    let (mut res, mut overflowed) = if (-modulus..modulus).contains(&rhs) {
        (lhs - rhs, false)
    } else {
        // 2*modulus to get all the bits
        (lhs - (rhs % (2 * modulus)), true)
    };

    if res < -modulus {
        // rem_euclid(modulus) would also work
        res = modulus + (res - -modulus);
        overflowed = true;
    } else if res > modulus - 1 {
        res = -modulus + (res - modulus);
        overflowed = true;
    }
    (res, overflowed)
}

pub(crate) fn signed_mul_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> i64 {
    assert!(modulus > 0);
    overflowing_mul_under_modulus(lhs, rhs, modulus).0
}

pub(crate) fn overflowing_mul_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> (i64, bool) {
    let (mut res, mut overflowed) = lhs.overflowing_mul(rhs);
    overflowed |= res < -modulus || res >= modulus;
    res %= modulus * 2;
    if res < -modulus {
        // rem_euclid(modulus) would also work
        res = modulus + (res - -modulus);
    } else if res > modulus - 1 {
        res = -modulus + (res - modulus);
    }

    (res, overflowed)
}

pub(crate) fn absolute_value_under_modulus(lhs: i64, modulus: i64) -> i64 {
    if lhs < 0 {
        signed_neg_under_modulus(lhs, modulus)
    } else {
        lhs
    }
}

pub(crate) fn signed_left_shift_under_modulus(lhs: i64, rhs: u32, modulus: i64) -> i64 {
    signed_mul_under_modulus(lhs, 1 << rhs, modulus)
}

pub(crate) fn signed_right_shift_under_modulus(lhs: i64, rhs: u32, _modulus: i64) -> i64 {
    lhs >> rhs
}

pub(crate) fn signed_div_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> i64 {
    // in signed integers, -modulus can be represented, but +modulus cannot
    // thus, when dividing: -128 / -1 = 128 the results overflows to -128
    assert!(modulus > 0);
    let mut res = lhs / rhs;
    if res < -modulus {
        // rem_euclid(modulus) would also work
        res = modulus + (res - -modulus);
    } else if res > modulus - 1 {
        res = -modulus + (res - modulus);
    }
    res
}

pub(crate) fn signed_rem_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> i64 {
    assert!(modulus > 0);
    let q = signed_div_under_modulus(lhs, rhs, modulus);
    let q_times_rhs = signed_mul_under_modulus(q, rhs, modulus);
    signed_sub_under_modulus(lhs, q_times_rhs, modulus)
}

pub(crate) fn signed_div_rem_floor_under_modulus(lhs: i64, rhs: i64, modulus: i64) -> (i64, i64) {
    let mut q = signed_div_under_modulus(lhs, rhs, modulus);
    let mut r = signed_rem_under_modulus(lhs, rhs, modulus);

    if (r != 0) && ((r < 0) != (rhs < 0)) {
        q = signed_sub_under_modulus(q, 1, modulus);
        r = signed_add_under_modulus(r, rhs, modulus);
    }

    (q, r)
}

/// helper function to do a rotate left when the type used to store
/// the value is bigger than the actual intended bit size
pub(crate) fn rotate_left_helper(value: i64, n: u32, actual_bit_size: u32) -> i64 {
    // We start with:
    // [0000000000000|xxxx]
    // 64           b    0
    //
    // rotated will be
    // [0000000000xx|xx00]
    // 64           b    0
    let n = n % actual_bit_size;
    let mask = 1i64.wrapping_shl(actual_bit_size) - 1;
    let shifted_mask = mask.wrapping_shl(n) & !mask;

    // Value maybe be negative and so, have its msb
    // set to one, so use mask to only keep the part that interest
    // us
    let rotated = (value & mask).rotate_left(n);

    let tmp = (rotated & mask) | ((rotated & shifted_mask) >> actual_bit_size);
    // If the sign bit after rotation is one,
    // then all bits above it needs to be one
    let new_sign_bit = (tmp >> (actual_bit_size - 1)) & 1;
    let mut pad = -new_sign_bit;
    pad <<= actual_bit_size; // only bits above actual_bit_size should be set

    pad | tmp
}

/// helper function to do a rotate right when the type used to store
/// the value is bigger than the actual intended bit size
pub(crate) fn rotate_right_helper(value: i64, n: u32, actual_bit_size: u32) -> i64 {
    // We start with:
    // [yyyyyyyyyyyy|xxxx]
    // 64           b    0
    // where xs are bits that we are interested in
    // and ys are either 0 or 1 depending on if value is positive
    //
    // mask: [yyyyyyyyyyyy|mmmm]
    // shifted_ mask: [mmyyyyyyyyyy|0000]
    //
    // rotated will be
    // [xxyyyyyyyyyy|00xx]
    // 64           b    0
    //
    // To get the 'cycled' bits where they should be,
    // we get them using a mask then shift
    let n = n % actual_bit_size;
    let mask = 1i64.wrapping_shl(actual_bit_size) - 1;
    // shifted mask only needs the bits that cycled
    let shifted_mask = mask.rotate_right(n) & !mask;

    // Value maybe be negative and so, have its msb
    // set to one, so use mask to only keep the part that interest
    // us
    let rotated = (value & mask).rotate_right(n);

    let tmp = (rotated & mask) | ((rotated & shifted_mask) >> (u64::BITS - actual_bit_size));
    // If the sign bit after rotation is one,
    // then all bits above it needs to be one
    let new_sign_bit = (tmp >> (actual_bit_size - 1)) & 1;
    let mut pad = -new_sign_bit;
    pad <<= actual_bit_size; // only bits above actual_bit_size should be set

    pad | tmp
}

/// Returns an array filled with random values such that:
/// - the first half contains values in [0..modulus[
/// - the second half contains values in [-modulus..0]
pub(crate) fn random_signed_value_under_modulus<const N: usize>(
    rng: &mut rand::prelude::ThreadRng,
    modulus: i64,
) -> [i64; N] {
    assert!(modulus > 0);

    let mut values = [0i64; N];

    for value in &mut values[..N / 2] {
        *value = rng.gen_range(0..modulus);
    }

    for value in &mut values[N / 2..] {
        *value = rng.gen_range(-modulus..=0);
    }

    values
}

/// Returns an array filled with random values such that:
/// - the first half contains values in ]0..modulus[
/// - the second half contains values in [-modulus..0[
pub(crate) fn random_non_zero_signed_value_under_modulus<const N: usize>(
    rng: &mut rand::prelude::ThreadRng,
    modulus: i64,
) -> [i64; N] {
    assert!(modulus > 0);

    let mut values = [0i64; N];

    for value in &mut values[..N / 2] {
        *value = rng.gen_range(1..modulus);
    }

    for value in &mut values[N / 2..] {
        *value = rng.gen_range(-modulus..0);
    }

    values
}

/// Returns an iterator that yields pairs of i64 values in range `-modulus..modulus`
/// such that there is at least one pair of (P, P), (P, N), (N, N) (N, P)
/// where P means value >=0 and N means <= 0
pub(crate) fn create_iterator_of_signed_random_pairs<const N: usize>(
    rng: &mut rand::prelude::ThreadRng,
    modulus: i64,
) -> impl Iterator<Item = (i64, i64)> {
    assert!(N >= 4, "N must be at least 4 to uphold the guarantee");
    let mut lhs_values = [0i64; N];
    let mut rhs_values = [0i64; N];

    lhs_values[0] = rng.gen_range(0..modulus);
    rhs_values[0] = rng.gen_range(0..modulus);

    lhs_values[1] = rng.gen_range(0..modulus);
    rhs_values[1] = rng.gen_range(-modulus..=0);

    lhs_values[2] = rng.gen_range(-modulus..=0);
    rhs_values[2] = rng.gen_range(-modulus..=0);

    lhs_values[3] = rng.gen_range(-modulus..=0);
    rhs_values[3] = rng.gen_range(0..modulus);

    for i in 4..N {
        lhs_values[i] = rng.gen_range(-modulus..modulus);
        rhs_values[i] = rng.gen_range(-modulus..modulus);
    }

    izip!(lhs_values, rhs_values)
}

pub(crate) fn random_non_zero_value(rng: &mut ThreadRng, modulus: i64) -> i64 {
    loop {
        let value = rng.gen::<i64>() % modulus;
        if value != 0 {
            break value;
        }
    }
}

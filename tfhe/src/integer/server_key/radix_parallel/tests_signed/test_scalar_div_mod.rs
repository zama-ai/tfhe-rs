use crate::integer::ciphertext::SignedRadixCiphertext;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::{
    random_non_zero_signed_value_under_modulus, random_signed_value_under_modulus,
    signed_div_under_modulus, signed_rem_under_modulus, NB_CTXT,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::CpuFunctionExecutor;
use crate::integer::tests::create_parameterized_test;
use crate::integer::{IntegerKeyKind, RadixClientKey, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use itertools::iproduct;
use rand::prelude::*;
use std::sync::Arc;

create_parameterized_test!(integer_signed_unchecked_scalar_div_rem);

fn integer_signed_unchecked_scalar_div_rem<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor =
        CpuFunctionExecutor::new(&ServerKey::unchecked_signed_scalar_div_rem_parallelized);
    signed_unchecked_scalar_div_rem_test(param, executor);
}

pub(crate) fn signed_unchecked_scalar_div_rem_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<
            (&'a SignedRadixCiphertext, i64),
            (SignedRadixCiphertext, SignedRadixCiphertext),
        > + std::panic::UnwindSafe,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let mut rng = rand::rng();
    let cks = RadixClientKey::from((cks, NB_CTXT));
    let sks = Arc::new(sks);

    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks.clone());

    // check when scalar is out of ciphertext MIN..=MAX
    for d in [
        rng.gen_range(i64::MIN..-modulus),
        rng.gen_range(modulus..=i64::MAX),
    ] {
        for numerator in [rng.gen_range(-modulus..=0), rng.gen_range(0..modulus)] {
            let ctxt_0 = cks.encrypt_signed(numerator);

            let (q_res, r_res) = executor.execute((&ctxt_0, d));
            let q: i64 = cks.decrypt_signed(&q_res);
            let r: i64 = cks.decrypt_signed(&r_res);
            assert_eq!(q, signed_div_under_modulus(numerator, d, modulus));
            assert_eq!(r, signed_rem_under_modulus(numerator, d, modulus));
        }
    }

    // The algorithm has a special case for when divisor is 1 or -1
    for d in [1i64, -1i64] {
        let clear_0 = rng.gen::<i64>() % modulus;

        let ctxt_0 = cks.encrypt_signed(clear_0);

        let (q_res, r_res) = executor.execute((&ctxt_0, d));
        let q: i64 = cks.decrypt_signed(&q_res);
        let r: i64 = cks.decrypt_signed(&r_res);
        assert_eq!(q, signed_div_under_modulus(clear_0, d, modulus));
        assert_eq!(r, signed_rem_under_modulus(clear_0, d, modulus));
    }

    // 3 / -3 takes the second branch in the if else if series
    for d in [3, -3] {
        {
            let neg_clear_0 = rng.gen_range(-modulus..=0);
            let ctxt_0 = cks.encrypt_signed(neg_clear_0);
            println!("{neg_clear_0} / {d}");
            let (q_res, r_res) = executor.execute((&ctxt_0, d));
            let q: i64 = cks.decrypt_signed(&q_res);
            let r: i64 = cks.decrypt_signed(&r_res);
            assert_eq!(q, signed_div_under_modulus(neg_clear_0, d, modulus));
            assert_eq!(r, signed_rem_under_modulus(neg_clear_0, d, modulus));
        }

        {
            let pos_clear_0 = rng.gen_range(0..modulus);
            let ctxt_0 = cks.encrypt_signed(pos_clear_0);
            println!("{pos_clear_0} / {d}");
            let (q_res, r_res) = executor.execute((&ctxt_0, d));
            let q: i64 = cks.decrypt_signed(&q_res);
            let r: i64 = cks.decrypt_signed(&r_res);
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
                let ctxt_0 = cks.encrypt_signed(neg_clear_0);
                let (q_res, r_res) = executor.execute((&ctxt_0, d));
                let q: i64 = cks.decrypt_signed(&q_res);
                let r: i64 = cks.decrypt_signed(&r_res);
                assert_eq!(q, signed_div_under_modulus(neg_clear_0, d, modulus));
                assert_eq!(r, signed_rem_under_modulus(neg_clear_0, d, modulus));
            }

            {
                let pos_clear_0 = rng.gen_range(0..modulus);
                let ctxt_0 = cks.encrypt_signed(pos_clear_0);
                println!("{pos_clear_0} / {d}");
                let (q_res, r_res) = executor.execute((&ctxt_0, d));
                let q: i64 = cks.decrypt_signed(&q_res);
                let r: i64 = cks.decrypt_signed(&r_res);
                assert_eq!(q, signed_div_under_modulus(pos_clear_0, d, modulus));
                assert_eq!(r, signed_rem_under_modulus(pos_clear_0, d, modulus));
            }
        }

        // For param_2_2 this will take the first branch
        for (clear_0, clear_1) in [(43, 8), (43, -8), (-43, 8), (-43, -8)] {
            let ctxt_0 = cks.encrypt_signed(clear_0);

            let (q_res, r_res) = executor.execute((&ctxt_0, clear_1));
            let q: i64 = cks.decrypt_signed(&q_res);
            let r: i64 = cks.decrypt_signed(&r_res);
            assert_eq!(q, signed_div_under_modulus(clear_0, clear_1, modulus));
            assert_eq!(r, signed_rem_under_modulus(clear_0, clear_1, modulus));
        }
    }

    for d in [-modulus, modulus - 1] {
        {
            let neg_clear_0 = rng.gen_range(-modulus..=0);
            let ctxt_0 = cks.encrypt_signed(neg_clear_0);
            let (q_res, r_res) = executor.execute((&ctxt_0, d));
            let q: i64 = cks.decrypt_signed(&q_res);
            let r: i64 = cks.decrypt_signed(&r_res);
            assert_eq!(q, signed_div_under_modulus(neg_clear_0, d, modulus));
            assert_eq!(r, signed_rem_under_modulus(neg_clear_0, d, modulus));
        }

        {
            let pos_clear_0 = rng.gen_range(0..modulus);
            let ctxt_0 = cks.encrypt_signed(pos_clear_0);
            let (q_res, r_res) = executor.execute((&ctxt_0, d));
            let q: i64 = cks.decrypt_signed(&q_res);
            let r: i64 = cks.decrypt_signed(&r_res);
            assert_eq!(q, signed_div_under_modulus(pos_clear_0, d, modulus));
            assert_eq!(r, signed_rem_under_modulus(pos_clear_0, d, modulus));
        }
    }

    let lhs_values = random_signed_value_under_modulus::<6>(&mut rng, modulus);
    let rhs_values = random_non_zero_signed_value_under_modulus::<6>(&mut rng, modulus);

    for (clear_lhs, clear_rhs) in iproduct!(lhs_values, rhs_values) {
        let ctxt_0 = cks.encrypt_signed(clear_lhs);

        let (q_res, r_res) = executor.execute((&ctxt_0, clear_rhs));
        let q: i64 = cks.decrypt_signed(&q_res);
        let r: i64 = cks.decrypt_signed(&r_res);
        assert_eq!(q, signed_div_under_modulus(clear_lhs, clear_rhs, modulus));
        assert_eq!(r, signed_rem_under_modulus(clear_lhs, clear_rhs, modulus));
    }

    // Do this test last, so we can move the executor into the closure
    let result = std::panic::catch_unwind(move || {
        let numerator = sks.create_trivial_radix(1, NB_CTXT);
        executor.execute((&numerator, 0i64));
    });
    assert!(result.is_err(), "division by zero should panic");
}

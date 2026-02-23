use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_for_params, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{IntegerKeyKind, RadixClientKey, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::prelude::*;
use std::sync::Arc;

create_parameterized_test!(integer_default_scalar_div_rem);

fn integer_default_scalar_div_rem<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_div_rem_parallelized);
    default_scalar_div_rem_test(param, executor);
}

pub(crate) fn default_scalar_div_rem_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<(&'a RadixCiphertext, u64), (RadixCiphertext, RadixCiphertext)>
        + std::panic::UnwindSafe,
{
    let param = param.into();
    let nb_tests = nb_tests_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);

    let num_block =
        (32f64 / (cks.parameters().message_modulus().0 as f64).log(2.0)).ceil() as usize;

    let cks = RadixClientKey::from((cks, num_block));
    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(num_block as u32);

    executor.setup(&cks, sks.clone());

    // the scalar is a u32, so the numerator must encrypt at least 32 bits
    // to take the normal path of execution
    assert!(modulus >= (1 << u32::BITS));

    // hard-coded tests
    // 10, 7, 14 are from the paper and should trigger different branches
    // 16 is a power of two and should trigger the corresponding branch
    let hard_coded_divisors: [u64; 4] = [10, 7, 14, 16];
    for divisor in hard_coded_divisors {
        let clear = rng.gen::<u64>() % modulus;
        let ct = cks.encrypt(clear);

        let (q, r) = executor.execute((&ct, divisor));

        let q_res: u64 = cks.decrypt(&q);
        let r_res: u64 = cks.decrypt(&r);
        assert_eq!(q_res, clear / divisor);
        assert_eq!(r_res, clear % divisor);
    }

    for _ in 0..nb_tests {
        let clear = rng.gen::<u64>() % modulus;
        let scalar = rng.gen_range(1u32..=u32::MAX) as u64;

        let ct = cks.encrypt(clear);

        {
            let (q, r) = executor.execute((&ct, scalar));
            let (q2, r2) = executor.execute((&ct, scalar));
            assert!(q.block_carries_are_empty());
            assert!(r.block_carries_are_empty());
            assert_eq!(q, q2);
            assert_eq!(q, q2, "Failed determinism check, \n\n\n msg: {clear}, scalar: {scalar}, \n\n\nctxt: {ct:?}\n\n\n");
            assert_eq!(r, r2, "Failed determinism check, \n\n\n msg: {clear}, scalar: {scalar}, \n\n\nctxt: {ct:?}\n\n\n");

            let q_res: u64 = cks.decrypt(&q);
            let r_res: u64 = cks.decrypt(&r);
            assert_eq!(q_res, clear / scalar);
            assert_eq!(r_res, clear % scalar);
        }

        {
            // Test when scalar is trivially bigger than the ct
            let scalar = rng.gen_range(u32::MAX as u64 + 1..=u64::MAX);

            let (q, r) = executor.execute((&ct, scalar));
            let (q2, r2) = executor.execute((&ct, scalar));
            assert!(q.block_carries_are_empty());
            assert!(r.block_carries_are_empty());
            assert_eq!(q, q2);
            assert_eq!(q, q2, "Failed determinism check, \n\n\n msg: {clear}, scalar: {scalar}, \n\n\nctxt: {ct:?}\n\n\n");
            assert_eq!(r, r2);
            assert_eq!(r, r2, "Failed determinism check, \n\n\n msg: {clear}, scalar: {scalar}, \n\n\nctxt: {ct:?}\n\n\n");

            let q_res: u64 = cks.decrypt(&q);
            let r_res: u64 = cks.decrypt(&r);
            assert_eq!(q_res, clear / scalar);
            assert_eq!(r_res, clear % scalar);
        }
    }

    // Do this test last, so we can move the executor into the closure
    let result = std::panic::catch_unwind(move || {
        let numerator = sks.create_trivial_radix(1, num_block);
        executor.execute((&numerator, 0u64));
    });
    assert!(result.is_err(), "division by zero should panic");
}

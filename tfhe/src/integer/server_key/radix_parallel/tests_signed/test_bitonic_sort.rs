use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::FunctionExecutor;
use crate::integer::server_key::radix_parallel::tests_signed::NB_CTXT;
use crate::integer::{IntegerKeyKind, RadixClientKey, SignedRadixCiphertext};
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

pub(crate) fn signed_unchecked_bitonic_sort_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: FunctionExecutor<Vec<SignedRadixCiphertext>, Vec<SignedRadixCiphertext>>,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    // Test 1: known values with negative numbers
    {
        let clear_values: Vec<i64> = vec![3, -7, 4, -1, 6, -2, 1, 5];
        let encrypted: Vec<SignedRadixCiphertext> = clear_values
            .iter()
            .map(|v| cks.encrypt_signed(*v))
            .collect();

        let sorted = executor.execute(encrypted);

        let decrypted: Vec<i64> = sorted.iter().map(|ct| cks.decrypt_signed(ct)).collect();
        let mut expected = clear_values;
        expected.sort_unstable();
        assert_eq!(decrypted, expected);
    }

    // Test 2: two elements
    {
        let a = rng.gen::<i64>() % modulus;
        let b = rng.gen::<i64>() % modulus;
        let clear_values: Vec<i64> = vec![a, b];
        let encrypted: Vec<SignedRadixCiphertext> = clear_values
            .iter()
            .map(|v| cks.encrypt_signed(*v))
            .collect();

        let sorted = executor.execute(encrypted);

        let decrypted: Vec<i64> = sorted.iter().map(|ct| cks.decrypt_signed(ct)).collect();
        let mut expected = clear_values;
        expected.sort_unstable();
        assert_eq!(decrypted, expected);
    }

    // Test 3: random values
    {
        let clear_values: Vec<i64> = (0..4).map(|_| rng.gen::<i64>() % modulus).collect();
        let encrypted: Vec<SignedRadixCiphertext> = clear_values
            .iter()
            .map(|v| cks.encrypt_signed(*v))
            .collect();

        let sorted = executor.execute(encrypted);

        let decrypted: Vec<i64> = sorted.iter().map(|ct| cks.decrypt_signed(ct)).collect();
        let mut expected = clear_values;
        expected.sort_unstable();
        assert_eq!(decrypted, expected);
    }
}

pub(crate) fn signed_default_bitonic_sort_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: FunctionExecutor<Vec<SignedRadixCiphertext>, Vec<SignedRadixCiphertext>>,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();
    let modulus = (cks.parameters().message_modulus().0.pow(NB_CTXT as u32) / 2) as i64;

    executor.setup(&cks, sks);

    {
        let clear_values: Vec<i64> = (0..4).map(|_| rng.gen::<i64>() % modulus).collect();
        let encrypted: Vec<SignedRadixCiphertext> = clear_values
            .iter()
            .map(|v| cks.encrypt_signed(*v))
            .collect();

        let sorted = executor.execute(encrypted);

        let decrypted: Vec<i64> = sorted.iter().map(|ct| cks.decrypt_signed(ct)).collect();
        let mut expected = clear_values;
        expected.sort_unstable();
        assert_eq!(decrypted, expected);
    }
}

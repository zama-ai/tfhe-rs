use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{FunctionExecutor, NB_CTXT};
use crate::integer::server_key::radix_parallel::tests_unsigned::unsigned_modulus;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey};
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

pub(crate) fn unchecked_bitonic_sort_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: FunctionExecutor<Vec<RadixCiphertext>, Vec<RadixCiphertext>>,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks);

    // Test 1: known values (power-of-2 length)
    {
        let clear_values: Vec<u64> = vec![3, 7, 4, 8, 6, 2, 1, 5];
        let encrypted: Vec<RadixCiphertext> =
            clear_values.iter().map(|v| cks.encrypt(*v)).collect();

        let sorted = executor.execute(encrypted);

        let decrypted: Vec<u64> = sorted.iter().map(|ct| cks.decrypt(ct)).collect();
        let mut expected = clear_values;
        expected.sort_unstable();
        assert_eq!(decrypted, expected);
    }

    // Test 2: two elements
    {
        let clear_values: Vec<u64> = vec![42 % modulus, 7 % modulus];
        let encrypted: Vec<RadixCiphertext> =
            clear_values.iter().map(|v| cks.encrypt(*v)).collect();

        let sorted = executor.execute(encrypted);

        let decrypted: Vec<u64> = sorted.iter().map(|ct| cks.decrypt(ct)).collect();
        let mut expected = clear_values;
        expected.sort_unstable();
        assert_eq!(decrypted, expected);
    }

    // Test 3: all same values
    {
        let val = rng.gen::<u64>() % modulus;
        let clear_values: Vec<u64> = vec![val; 4];
        let encrypted: Vec<RadixCiphertext> =
            clear_values.iter().map(|v| cks.encrypt(*v)).collect();

        let sorted = executor.execute(encrypted);

        let decrypted: Vec<u64> = sorted.iter().map(|ct| cks.decrypt(ct)).collect();
        assert_eq!(decrypted, clear_values);
    }

    // Test 4: random values
    {
        let clear_values: Vec<u64> = (0..4).map(|_| rng.gen::<u64>() % modulus).collect();
        let encrypted: Vec<RadixCiphertext> =
            clear_values.iter().map(|v| cks.encrypt(*v)).collect();

        let sorted = executor.execute(encrypted);

        let decrypted: Vec<u64> = sorted.iter().map(|ct| cks.decrypt(ct)).collect();
        let mut expected = clear_values;
        expected.sort_unstable();
        assert_eq!(decrypted, expected);
    }
}

pub(crate) fn default_bitonic_sort_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: FunctionExecutor<Vec<RadixCiphertext>, Vec<RadixCiphertext>>,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let sks = Arc::new(sks);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();
    let modulus = unsigned_modulus(cks.parameters().message_modulus(), NB_CTXT as u32);

    executor.setup(&cks, sks);

    // Test with random values
    {
        let clear_values: Vec<u64> = (0..4).map(|_| rng.gen::<u64>() % modulus).collect();
        let encrypted: Vec<RadixCiphertext> =
            clear_values.iter().map(|v| cks.encrypt(*v)).collect();

        let sorted = executor.execute(encrypted);

        let decrypted: Vec<u64> = sorted.iter().map(|ct| cks.decrypt(ct)).collect();
        let mut expected = clear_values;
        expected.sort_unstable();
        assert_eq!(decrypted, expected);
    }
}

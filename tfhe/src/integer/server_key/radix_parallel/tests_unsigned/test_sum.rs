use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{FunctionExecutor, NB_CTXT};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    nb_tests_smaller_for_params, overflowing_sum_slice_under_modulus, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

create_parameterized_test!(integer_smart_sum_ciphertexts_slice);
create_parameterized_test!(integer_default_unsigned_overflowing_sum_ciphertexts_vec);
create_parameterized_test!(integer_default_sum_ciphertexts_vec);

fn integer_default_unsigned_overflowing_sum_ciphertexts_vec<P>(param: P)
where
    P: Into<TestParameters>,
{
    integer_default_unsigned_overflowing_sum_ciphertexts_test(param);
}

fn integer_default_sum_ciphertexts_vec<P>(param: P)
where
    P: Into<TestParameters>,
{
    // Without this the compiler seems lost, and outputs errors about
    // 'one type is more general than the other' probably because the
    // `sum_ciphertexts_parallelized` is generic over the input collection
    let sum_vec = |sks: &ServerKey, ctxt: &Vec<RadixCiphertext>| -> Option<RadixCiphertext> {
        sks.sum_ciphertexts_parallelized(ctxt)
    };
    let executor = CpuFunctionExecutor::new(sum_vec);
    default_sum_ciphertexts_vec_test(param, executor);
}

pub(crate) fn integer_default_unsigned_overflowing_sum_ciphertexts_test<P>(param: P)
where
    P: Into<TestParameters>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    for len in [1, 2, 15, 16, 17, 64, 65] {
        for _ in 0..nb_tests_smaller {
            let clears = (0..len)
                .map(|_| rng.gen::<u64>() % modulus)
                .collect::<Vec<_>>();

            let ctxts = clears
                .iter()
                .copied()
                .map(|clear| cks.encrypt(clear))
                .collect::<Vec<_>>();

            let (ct_res, overflow_res) = sks
                .unsigned_overflowing_sum_ciphertexts_parallelized(&ctxts)
                .unwrap();

            assert_eq!(
                overflow_res.0.degree.get(),
                if len == 1 { 0 } else { 1 },
                "invalid degree"
            );
            assert_eq!(
                overflow_res.0.noise_level(),
                if len == 1 {
                    NoiseLevel::ZERO
                } else {
                    NoiseLevel::NOMINAL
                },
                "invalid noise level"
            );

            let decrypted_res: u64 = cks.decrypt(&ct_res);
            let decrypted_overflow = cks.decrypt_bool(&overflow_res);

            let (expected_clear, expected_overflow) =
                overflowing_sum_slice_under_modulus(&clears, modulus);

            assert_eq!(decrypted_res, expected_clear,
            "Invalid result for sum of ciphertext, expected {expected_clear} got {decrypted_res}");
            assert_eq!(decrypted_overflow, expected_overflow,
            "Invalid result for overflow flag of sum of ciphertext, expected {decrypted_overflow} got {expected_overflow}");
        }
    }

    // Tests on trivial ciphertexts
    for len in [3, 4, 64] {
        for _ in 0..nb_tests_smaller {
            let clears = (0..len)
                .map(|_| rng.gen::<u64>() % modulus)
                .collect::<Vec<_>>();

            let ctxts = clears
                .iter()
                .copied()
                .map(|clear| sks.create_trivial_radix(clear, NB_CTXT))
                .collect::<Vec<_>>();

            let (ct_res, overflow_res) = sks
                .unsigned_overflowing_sum_ciphertexts_parallelized(&ctxts)
                .unwrap();

            assert_eq!(
                overflow_res.0.degree.get(),
                if len == 1 { 0 } else { 1 },
                "invalid degree"
            );
            assert_eq!(
                overflow_res.0.noise_level(),
                NoiseLevel::ZERO,
                "invalid noise level"
            );

            let decrypted_res: u64 = cks.decrypt(&ct_res);
            let decrypted_overflow = cks.decrypt_bool(&overflow_res);

            let (expected_clear, expected_overflow) =
                overflowing_sum_slice_under_modulus(&clears, modulus);

            assert_eq!(decrypted_res, expected_clear,
                       "Invalid result for sum of ciphertext, expected {expected_clear} got {decrypted_res}");
            assert_eq!(decrypted_overflow, expected_overflow,
                       "Invalid result for overflow flag of sum of ciphertext, expected {decrypted_overflow} got {expected_overflow}");
        }
    }
}

pub(crate) fn default_sum_ciphertexts_vec_test<P, T>(param: P, mut executor: T)
where
    P: Into<TestParameters>,
    T: for<'a> FunctionExecutor<&'a Vec<RadixCiphertext>, Option<RadixCiphertext>>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, mut sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((
        cks,
        crate::integer::server_key::radix_parallel::tests_unsigned::NB_CTXT,
    ));
    sks.set_deterministic_pbs_execution(true);
    let sks = Arc::new(sks);

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks
        .parameters()
        .message_modulus()
        .0
        .pow(crate::integer::server_key::radix_parallel::tests_unsigned::NB_CTXT as u32);

    executor.setup(&cks, sks);

    for len in [1, 2, 15, 16, 17, 64, 65] {
        for _ in 0..nb_tests_smaller {
            let clears = (0..len)
                .map(|_| rng.gen::<u64>() % modulus)
                .collect::<Vec<_>>();

            let ctxts = clears
                .iter()
                .copied()
                .map(|clear| cks.encrypt(clear))
                .collect::<Vec<_>>();

            let ct_res = executor.execute(&ctxts).unwrap();
            let res: u64 = cks.decrypt(&ct_res);
            let clear = clears.iter().sum::<u64>() % modulus;

            assert_eq!(res, clear);

            let ct_res_2 = executor.execute(&ctxts).unwrap();
            assert_eq!(ct_res, ct_res_2, "Failed determinism check");
        }
    }
}

fn integer_smart_sum_ciphertexts_slice<P>(param: P)
where
    P: Into<TestParameters>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32);

    for len in [1, 2, 15, 16, 17, 64, 65] {
        for _ in 0..nb_tests_smaller {
            let clears = (0..len)
                .map(|_| rng.gen::<u64>() % modulus)
                .collect::<Vec<_>>();

            // encryption of integers
            let mut ctxts = clears
                .iter()
                .copied()
                .map(|clear| cks.encrypt(clear))
                .collect::<Vec<_>>();

            let ct_res = sks.smart_sum_ciphertexts_parallelized(&mut ctxts).unwrap();
            let ct_res: u64 = cks.decrypt(&ct_res);
            let clear = clears.iter().sum::<u64>() % modulus;

            assert_eq!(ct_res, clear);
        }
    }
}

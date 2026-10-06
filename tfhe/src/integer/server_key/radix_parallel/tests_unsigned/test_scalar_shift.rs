use crate::integer::keycache::KEY_CACHE;
use crate::integer::server_key::radix_parallel::tests_cases_unsigned::{
    default_scalar_left_shift_test, default_scalar_right_shift_test,
    unchecked_scalar_left_shift_test, unchecked_scalar_right_shift_test,
};
use crate::integer::server_key::radix_parallel::tests_unsigned::{
    large_shift_amounts, CpuFunctionExecutor,
};
use crate::integer::tests::create_parameterized_test;
use crate::integer::{IntegerKeyKind, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::test_params::*;
use crate::shortint::parameters::*;
use rand::Rng;

create_parameterized_test!(integer_unchecked_scalar_left_shift);
create_parameterized_test!(integer_default_scalar_left_shift);
create_parameterized_test!(integer_unchecked_scalar_right_shift);
create_parameterized_test!(integer_default_scalar_right_shift);
create_parameterized_test!(integer_default_scalar_shift_large_amount);

fn integer_default_scalar_left_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_left_shift_parallelized);
    default_scalar_left_shift_test(param, executor);
}

fn integer_unchecked_scalar_left_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_left_shift_parallelized);
    unchecked_scalar_left_shift_test(param, executor);
}

fn integer_default_scalar_right_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_right_shift_parallelized);
    default_scalar_right_shift_test(param, executor);
}

fn integer_unchecked_scalar_right_shift<P>(param: P)
where
    P: Into<TestParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_right_shift_parallelized);
    unchecked_scalar_right_shift_test(param, executor);
}

/// Non regression test: amounts that do not fit in a u64 were truncated to their low 64 bits,
/// turning an overshift into a regular shift.
fn integer_default_scalar_shift_large_amount<P>(param: P)
where
    P: Into<TestParameters>,
{
    let param = param.into();
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let mut rng = rand::thread_rng();
    let bits_per_block = cks.parameters().message_modulus().0.ilog2();

    for num_blocks in [3, 5] {
        let nb_bits = bits_per_block * num_blocks as u32;
        // With its lowest and highest bits set, any shift below the bit count leaves a bit set
        let values = [1 | (1 << (nb_bits - 1)), rng.gen_range(1..1u64 << nb_bits)];
        for clear in values {
            let ct = cks.encrypt_radix(clear, num_blocks);
            for amount in large_shift_amounts(&mut rng, nb_bits) {
                // Every amount overshifts
                for (name, result) in [
                    ("left", sks.scalar_left_shift_parallelized(&ct, amount)),
                    ("right", sks.scalar_right_shift_parallelized(&ct, amount)),
                    (
                        "non parallel left",
                        sks.unchecked_scalar_left_shift(&ct, amount),
                    ),
                    (
                        "non parallel right",
                        sks.unchecked_scalar_right_shift(&ct, amount),
                    ),
                ] {
                    assert!(result.block_carries_are_empty());
                    let decrypted: u64 = cks.decrypt_radix(&result);
                    assert_eq!(
                        decrypted, 0,
                        "invalid {name} shift of {clear} by {amount} ({nb_bits} bits)"
                    );
                }
            }
        }
    }
}

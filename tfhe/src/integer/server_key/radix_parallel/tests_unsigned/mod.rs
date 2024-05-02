pub(crate) mod old_tests_unsigned;
pub(crate) mod test_vector_comparisons;

use super::tests_cases_unsigned::*;
use crate::integer::keycache::KEY_CACHE;
use crate::integer::{BooleanBlock, IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
#[cfg(tarpaulin)]
use crate::shortint::parameters::coverage_parameters::*;
use crate::shortint::parameters::*;
use rand::Rng;
use std::sync::Arc;

#[cfg(not(tarpaulin))]
pub(crate) const NB_CTXT: usize = 4;
#[cfg(tarpaulin)]
pub(crate) const NB_CTXT: usize = 2;

#[cfg(not(tarpaulin))]
pub(crate) const MAX_VEC_LEN: usize = 25;
#[cfg(tarpaulin)]
pub(crate) const MAX_VEC_LEN: usize = 5;

/// Returns th number of loop iteration within randomized tests
///
/// The bigger the number of bits bootstrapped by the input parameters, the smaller the
/// number of iteration is
pub(crate) const fn nb_tests_for_params(params: PBSParameters) -> usize {
    let full_modulus = params.message_modulus().0 * params.carry_modulus().0;

    if cfg!(tarpaulin) {
        // Use lower numbers for coverage to ensure fast tests to counter balance slowdown due to
        // code instrumentation
        1
    } else {
        // >= 8 bits (4_4)
        if full_modulus >= 1 << 8 {
            return 5;
        }

        // >= 6 bits (3_3)
        if full_modulus >= 1 << 6 {
            return 15;
        }

        30
    }
}

/// Smaller number of loop iteration within randomized test,
/// meant for test where the function tested is more expensive
pub(crate) const fn nb_tests_smaller_for_params(params: PBSParameters) -> usize {
    let full_modulus = params.message_modulus().0 * params.carry_modulus().0;

    if cfg!(tarpaulin) {
        1
    } else {
        // >= 8 bits (4_4)
        if full_modulus >= 1 << 8 {
            return 2;
        }

        // >= 6 bits (3_3)
        if full_modulus >= 1 << 6 {
            return 5;
        }

        10
    }
}

pub(crate) fn unsigned_modulus(block_modulus: MessageModulus, num_blocks: u32) -> u64 {
    (block_modulus.0 as u64)
        .checked_pow(num_blocks)
        .expect("Modulus exceed u64::MAX")
}

create_parametrized_test!(integer_smart_sum_ciphertexts_slice);
create_parametrized_test!(integer_default_unsigned_overflowing_sum_ciphertexts_vec);
// left/right shifts
create_parametrized_test!(integer_unchecked_left_shift {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
});
create_parametrized_test!(integer_unchecked_right_shift {
    // This algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
});
// left/right rotations
create_parametrized_test!(integer_unchecked_rotate_left {
    // This algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
});
create_parametrized_test!(integer_unchecked_rotate_right {
    // This algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS,
});
// left/right rotations
create_parametrized_test!(integer_default_scalar_div_rem);
create_parametrized_test!(integer_trim_radix_msb_blocks_handles_dirty_inputs);
create_parametrized_test!(integer_full_propagate {
    PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_2_CARRY_3_KS_PBS, // Test case where carry_modulus > message_modulus
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
});

/// The function executor for cpu server key
///
/// It will mainly simply forward call to a server key method
pub(crate) struct CpuFunctionExecutor<F> {
    /// The server key is set later, when the test cast calls setup
    pub(crate) sks: Option<Arc<ServerKey>>,
    /// The server key function which will be called
    pub(crate) func: F,
}

impl<F> CpuFunctionExecutor<F> {
    pub(crate) fn new(func: F) -> Self {
        Self { sks: None, func }
    }
}

/// For unary function
///
/// Note, we don't do
/// impl<F, I, O> TestExecutor<I, O> for CpuTestExecutor<F>
/// where F: Fn(&ServerKey, I) -> O {}
/// As it would conflict with other impls.
///
/// impl<F, I1, O> TestExecutor<(I,), O> for CpuTestExecutor<F>
/// would be possible tho.
impl<'a, F> FunctionExecutor<&'a RadixCiphertext, (RadixCiphertext, BooleanBlock)>
    for CpuFunctionExecutor<F>
where
    F: Fn(&ServerKey, &RadixCiphertext) -> (RadixCiphertext, BooleanBlock),
{
    fn setup(&mut self, _cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.sks = Some(sks);
    }

    fn execute(&mut self, input: &'a RadixCiphertext) -> (RadixCiphertext, BooleanBlock) {
        let sks = self.sks.as_ref().expect("setup was not properly called");
        (self.func)(sks, input)
    }
}

impl<'a, F> FunctionExecutor<&'a RadixCiphertext, RadixCiphertext> for CpuFunctionExecutor<F>
where
    F: Fn(&ServerKey, &RadixCiphertext) -> RadixCiphertext,
{
    fn setup(&mut self, _cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.sks = Some(sks);
    }

    fn execute(&mut self, input: &'a RadixCiphertext) -> RadixCiphertext {
        let sks = self.sks.as_ref().expect("setup was not properly called");
        (self.func)(sks, input)
    }
}

impl<'a, F> FunctionExecutor<&'a Vec<RadixCiphertext>, Option<RadixCiphertext>>
    for CpuFunctionExecutor<F>
where
    F: Fn(&ServerKey, &Vec<RadixCiphertext>) -> Option<RadixCiphertext>,
{
    fn setup(&mut self, _cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.sks = Some(sks);
    }

    fn execute(&mut self, input: &'a Vec<RadixCiphertext>) -> Option<RadixCiphertext> {
        let sks = self.sks.as_ref().expect("setup was not properly called");
        (self.func)(sks, input)
    }
}

/// Unary assign fn
impl<'a, F> FunctionExecutor<&'a mut RadixCiphertext, ()> for CpuFunctionExecutor<F>
where
    F: Fn(&ServerKey, &'a mut RadixCiphertext),
{
    fn setup(&mut self, _cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.sks = Some(sks);
    }

    fn execute(&mut self, input: &'a mut RadixCiphertext) {
        let sks = self.sks.as_ref().expect("setup was not properly called");
        (self.func)(sks, input);
    }
}

impl<'a, F> FunctionExecutor<&'a mut RadixCiphertext, RadixCiphertext> for CpuFunctionExecutor<F>
where
    F: Fn(&ServerKey, &mut RadixCiphertext) -> RadixCiphertext,
{
    fn setup(&mut self, _cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.sks = Some(sks);
    }

    fn execute(&mut self, input: &'a mut RadixCiphertext) -> RadixCiphertext {
        let sks = self.sks.as_ref().expect("setup was not properly called");
        (self.func)(sks, input)
    }
}

/// For binary operations
impl<F, I1, I2, O> FunctionExecutor<(I1, I2), O> for CpuFunctionExecutor<F>
where
    F: Fn(&ServerKey, I1, I2) -> O,
{
    fn setup(&mut self, _cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.sks = Some(sks);
    }

    fn execute(&mut self, input: (I1, I2)) -> O {
        let sks = self.sks.as_ref().expect("setup was not properly called");
        (self.func)(sks, input.0, input.1)
    }
}

/// For ternary operations
impl<F, I1, I2, I3, O> FunctionExecutor<(I1, I2, I3), O> for CpuFunctionExecutor<F>
where
    F: Fn(&ServerKey, I1, I2, I3) -> O,
{
    fn setup(&mut self, _cks: &RadixClientKey, sks: Arc<ServerKey>) {
        self.sks = Some(sks);
    }

    fn execute(&mut self, input: (I1, I2, I3)) -> O {
        let sks = self.sks.as_ref().expect("setup was not properly called");
        (self.func)(sks, input.0, input.1, input.2)
    }
}

//=============================================================================
// Unchecked Tests
//=============================================================================

fn integer_unchecked_left_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_left_shift_parallelized);
    unchecked_left_shift_test(param, executor);
}

fn integer_unchecked_right_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_right_shift_parallelized);
    unchecked_right_shift_test(param, executor);
}

fn integer_unchecked_rotate_left<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_rotate_left_parallelized);
    unchecked_rotate_left_test(param, executor);
}

fn integer_unchecked_rotate_right<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_rotate_right_parallelized);
    unchecked_rotate_right_test(param, executor);
}

//=============================================================================
// Unchecked Scalar Tests
//=============================================================================

//=============================================================================
// Smart Tests
//=============================================================================

fn integer_smart_sum_ciphertexts_slice<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let param = param.into();
    let nb_tests_smaller = nb_tests_smaller_for_params(param);
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

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

fn integer_default_unsigned_overflowing_sum_ciphertexts_vec<P>(param: P)
where
    P: Into<PBSParameters>,
{
    integer_default_unsigned_overflowing_sum_ciphertexts_test(param);
}

//=============================================================================
// Smart Scalar Tests
//=============================================================================

//=============================================================================
// Default Tests
//=============================================================================

fn integer_default_scalar_div_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_div_rem_parallelized);
    default_scalar_div_rem_test(param, executor);
}

#[test]
#[cfg(not(tarpaulin))]
fn test_non_regression_clone_from() {
    // Issue: https://github.com/zama-ai/tfhe-rs/issues/410
    let (client_key, server_key) =
        KEY_CACHE.get_from_params(PARAM_MESSAGE_2_CARRY_2, IntegerKeyKind::Radix);
    let num_block: usize = 4;
    let a: u8 = 248;
    let b: u8 = 249;
    let c: u8 = 250;
    let d: u8 = 251;

    let enc_a = client_key.encrypt_radix(a, num_block);
    let enc_b = client_key.encrypt_radix(b, num_block);
    let enc_c = client_key.encrypt_radix(c, num_block);
    let enc_d = client_key.encrypt_radix(d, num_block);

    let (mut q1, mut r1) = server_key.div_rem_parallelized(&enc_b, &enc_a);
    let (mut q2, mut r2) = server_key.div_rem_parallelized(&enc_d, &enc_c);

    assert_eq!(client_key.decrypt_radix::<u8>(&r1), 1);
    assert_eq!(client_key.decrypt_radix::<u8>(&r2), 1);
    assert_eq!(client_key.decrypt_radix::<u8>(&q1), 1);
    assert_eq!(client_key.decrypt_radix::<u8>(&q2), 1);

    // The consequence of the bug was that r1r2 would be 0 instead of one
    let r1r2 = server_key.smart_mul_parallelized(&mut r1, &mut r2);
    assert_eq!(client_key.decrypt_radix::<u8>(&r1r2), 1);
    let q1q2 = server_key.smart_mul_parallelized(&mut q1, &mut q2);
    assert_eq!(client_key.decrypt_radix::<u8>(&q1q2), 1);
}

fn integer_trim_radix_msb_blocks_handles_dirty_inputs<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let param = param.into();
    let (client_key, server_key) = crate::integer::gen_keys_radix(param, NB_CTXT);
    let modulus = (param.message_modulus().0 as u64)
        .checked_pow(NB_CTXT as u32)
        .expect("modulus of ciphertext exceed u64::MAX");
    let num_bits = param.message_modulus().0.ilog2() * NB_CTXT as u32;

    let msg1 = 1u64 << (num_bits - 1);
    let msg2 = 1u64 << (num_bits - 1);

    let mut ct_1 = client_key.encrypt(msg1);
    let mut ct_2 = client_key.encrypt(msg2);

    // We are now working on modulus * modulus
    server_key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut ct_1, NB_CTXT);
    server_key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut ct_2, NB_CTXT);

    let mut ct_3 = server_key.unchecked_add_parallelized(&ct_1, &ct_2);
    let output: u64 = client_key.decrypt(&ct_3);
    // Seems to be a false positive
    #[allow(clippy::suspicious_operation_groupings)]
    {
        assert_eq!(output, (msg2 + msg1) % (modulus * modulus));
    }
    assert_ne!(output, (msg2 + msg1) % (modulus));

    server_key.trim_radix_blocks_msb_assign(&mut ct_3, NB_CTXT);

    let output: u64 = client_key.decrypt(&ct_3);
    assert_eq!(output, (msg2 + msg1) % (modulus));

    // If the trim radix did not clean carries, the result of output
    // would still be on modulus * modulus
    server_key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut ct_3, NB_CTXT);
    let output: u64 = client_key.decrypt(&ct_3);
    assert_eq!(output, (msg2 + msg1) % (modulus));
}

fn integer_full_propagate<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::full_propagate_parallelized);
    full_propagate_test(param, executor);
}

use crate::integer::keycache::KEY_CACHE;
use crate::integer::{IntegerKeyKind, RadixCiphertext, RadixClientKey, ServerKey};
use crate::shortint::parameters::*;
use paste::paste;
use rand::Rng;
use std::sync::Arc;

use super::tests_cases_unsigned::*;

/// Smaller number of loop iteration within randomized test,
/// meant for test where the function tested is more expensive
const NB_TESTS_SMALLER: usize = 10;
const NB_CTXT: usize = 4;

macro_rules! create_parametrized_test{
    ($name:ident { $($param:ident),* }) => {
        paste! {
            $(
            #[test]
            fn [<test_ $name _ $param:lower>]() {
                $name($param)
            }
            )*
        }
    };
     ($name:ident)=> {
        create_parametrized_test!($name
        {
            PARAM_MESSAGE_1_CARRY_1_KS_PBS,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS,
            PARAM_MESSAGE_3_CARRY_3_KS_PBS,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_1_CARRY_1_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
            PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
        });
    };
}

create_parametrized_test!(integer_smart_div_rem {
    // Due to the use of comparison,
    // this algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_smart_div {
    // Due to the use of comparison,
    // this algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_smart_rem {
    // Due to the use of comparison,
    // this algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_default_div_rem {
    // Due to the use of comparison,
    // this algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_default_rem {
    // Due to the use of comparison,
    // this algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_default_div {
    // Due to the use of comparison,
    // this algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_smart_add);
create_parametrized_test!(integer_smart_sum_ciphertexts_slice);
create_parametrized_test!(integer_default_sum_ciphertexts_vec);
create_parametrized_test!(integer_default_add);
create_parametrized_test!(integer_default_overflowing_add);
create_parametrized_test!(integer_default_add_work_efficient {
    // This algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_smart_bitand);
create_parametrized_test!(integer_smart_bitor);
create_parametrized_test!(integer_smart_bitxor);
create_parametrized_test!(integer_default_bitand);
create_parametrized_test!(integer_default_bitor);
create_parametrized_test!(integer_default_bitnot);
create_parametrized_test!(integer_default_bitxor);
create_parametrized_test!(integer_default_scalar_bitand);
create_parametrized_test!(integer_default_scalar_bitor);
create_parametrized_test!(integer_default_scalar_bitxor);
create_parametrized_test!(integer_unchecked_small_scalar_mul);
create_parametrized_test!(integer_smart_small_scalar_mul);
create_parametrized_test!(integer_default_small_scalar_mul);
create_parametrized_test!(integer_smart_scalar_mul_u128_fix_non_reg_test {
    PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS
});
create_parametrized_test!(integer_unchecked_mul_corner_cases);
create_parametrized_test!(integer_unchecked_scalar_mul_corner_cases);
create_parametrized_test!(integer_default_scalar_mul_u128_fix_non_reg_test {
    PARAM_MESSAGE_2_CARRY_2_KS_PBS
});
create_parametrized_test!(integer_smart_scalar_mul);
create_parametrized_test!(integer_default_scalar_mul);
// scalar left/right shifts
create_parametrized_test!(integer_unchecked_scalar_left_shift);
create_parametrized_test!(integer_default_scalar_left_shift);
create_parametrized_test!(integer_unchecked_scalar_right_shift);
create_parametrized_test!(integer_default_scalar_right_shift);
// left/right shifts
create_parametrized_test!(integer_unchecked_left_shift {
    // This algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_unchecked_right_shift {
    // This algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
// left/right rotations
create_parametrized_test!(integer_unchecked_rotate_left {
    // This algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_unchecked_rotate_right {
    // This algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
// left/right rotations
create_parametrized_test!(integer_unchecked_scalar_rotate_right);
create_parametrized_test!(integer_unchecked_scalar_rotate_left);
create_parametrized_test!(integer_default_scalar_rotate_right);
create_parametrized_test!(integer_default_scalar_rotate_left);
// negations
create_parametrized_test!(integer_smart_neg);
create_parametrized_test!(integer_default_neg);
create_parametrized_test!(integer_smart_sub);
create_parametrized_test!(integer_default_sub);
create_parametrized_test!(integer_default_overflowing_sub);
create_parametrized_test!(integer_default_sub_work_efficient {
    // This algorithm requires 3 bits
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});
create_parametrized_test!(integer_default_scalar_div_rem);
create_parametrized_test!(integer_unchecked_block_mul);
create_parametrized_test!(integer_smart_block_mul);
create_parametrized_test!(integer_default_block_mul);
create_parametrized_test!(integer_smart_mul);
create_parametrized_test!(integer_default_mul);
create_parametrized_test!(integer_smart_scalar_sub);
create_parametrized_test!(integer_default_scalar_sub);
create_parametrized_test!(integer_default_overflowing_scalar_sub);
create_parametrized_test!(integer_smart_scalar_add);
create_parametrized_test!(integer_default_scalar_add);
create_parametrized_test!(integer_default_overflowing_scalar_add);
create_parametrized_test!(integer_smart_if_then_else);
create_parametrized_test!(integer_default_if_then_else);
create_parametrized_test!(integer_trim_radix_msb_blocks_handles_dirty_inputs);

create_parametrized_test!(integer_unchecked_add);
create_parametrized_test!(integer_unchecked_mul);

create_parametrized_test!(integer_unchecked_add_assign);
create_parametrized_test!(integer_full_propagate {
    PARAM_MESSAGE_1_CARRY_1_KS_PBS,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_MESSAGE_2_CARRY_3_KS_PBS, // Test case where carry_modulus > message_modulus
    PARAM_MESSAGE_3_CARRY_3_KS_PBS,
    PARAM_MESSAGE_4_CARRY_4_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_2_KS_PBS,
    PARAM_MULTI_BIT_MESSAGE_3_CARRY_3_GROUP_3_KS_PBS
});

/// The function executor for cpu server key
///
/// It will mainly simply forward call to a server key method
pub(crate) struct CpuFunctionExecutor<F> {
    /// The server key is set later, when the test cast calls setup
    sks: Option<Arc<ServerKey>>,
    /// The server key function which will be called
    func: F,
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

fn integer_unchecked_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_add_parallelized);
    unchecked_add_test(param, executor);
}

fn integer_unchecked_add_assign<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_add_assign_parallelized);
    unchecked_add_assign_test(param, executor);
}

fn integer_unchecked_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_mul_parallelized);
    unchecked_mul_test(param, executor);
}

fn integer_unchecked_block_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_block_mul_parallelized);
    unchecked_block_mul_test(param, executor);
}

fn integer_unchecked_mul_corner_cases<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_mul_parallelized);
    unchecked_mul_corner_cases_test(param, executor);
}

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

fn integer_unchecked_small_scalar_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_small_scalar_mul_parallelized);
    unchecked_small_scalar_mul_test(param, executor);
}

fn integer_unchecked_scalar_mul_corner_cases<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_mul_parallelized);
    unchecked_scalar_mul_corner_cases_test(param, executor);
}

fn integer_unchecked_scalar_left_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_left_shift_parallelized);
    unchecked_scalar_left_shift_test(param, executor);
}

fn integer_unchecked_scalar_right_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_right_shift_parallelized);
    unchecked_scalar_right_shift_test(param, executor);
}

fn integer_unchecked_scalar_rotate_right<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_rotate_right_parallelized);
    unchecked_scalar_rotate_right_test(param, executor);
}

fn integer_unchecked_scalar_rotate_left<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unchecked_scalar_rotate_left_parallelized);
    unchecked_scalar_rotate_left_test(param, executor);
}

//=============================================================================
// Smart Tests
//=============================================================================

fn integer_smart_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_add_parallelized);
    smart_add_test(param, executor);
}

fn integer_smart_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_sub_parallelized);
    smart_sub_test(param, executor);
}

fn integer_smart_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_mul_parallelized);
    smart_mul_test(param, executor);
}

fn integer_smart_neg<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_neg_parallelized);
    smart_neg_test(param, executor);
}

fn integer_smart_bitand<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_bitand_parallelized);
    smart_bitand_test(param, executor);
}

fn integer_smart_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_bitor_parallelized);
    smart_bitor_test(param, executor);
}

fn integer_smart_bitxor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_bitxor_parallelized);
    smart_bitxor_test(param, executor);
}

fn integer_smart_if_then_else<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_if_then_else_parallelized);
    smart_if_then_else_test(param, executor);
}

fn integer_smart_div_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_div_rem_parallelized);
    smart_div_rem_test(param, executor);
}

fn integer_smart_div<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_div_parallelized);
    smart_div_test(param, executor);
}

fn integer_smart_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_rem_parallelized);
    smart_rem_test(param, executor);
}

fn integer_smart_sum_ciphertexts_slice<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for len in [1, 2, 15, 16, 17, 64, 65] {
        for _ in 0..NB_TESTS_SMALLER {
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

fn integer_default_sum_ciphertexts_vec<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let (cks, sks) = KEY_CACHE.get_from_params(param, IntegerKeyKind::Radix);
    let cks = RadixClientKey::from((cks, NB_CTXT));

    //RNG
    let mut rng = rand::thread_rng();

    // message_modulus^vec_length
    let modulus = cks.parameters().message_modulus().0.pow(NB_CTXT as u32) as u64;

    for len in [1, 2, 15, 16, 17, 64, 65] {
        for _ in 0..NB_TESTS_SMALLER {
            let clears = (0..len)
                .map(|_| rng.gen::<u64>() % modulus)
                .collect::<Vec<_>>();

            // encryption of integers
            let ctxts = clears
                .iter()
                .copied()
                .map(|clear| cks.encrypt(clear))
                .collect::<Vec<_>>();

            let ct_res = sks.sum_ciphertexts_parallelized(&ctxts).unwrap();
            let ct_res: u64 = cks.decrypt(&ct_res);
            let clear = clears.iter().sum::<u64>() % modulus;

            assert_eq!(ct_res, clear);
        }
    }
}

//=============================================================================
// Smart Scalar Tests
//=============================================================================

fn integer_smart_scalar_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_add_parallelized);
    smart_scalar_add_test(param, executor);
}

fn integer_smart_scalar_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_sub_parallelized);
    smart_scalar_sub_test(param, executor);
}

fn integer_smart_small_scalar_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_small_scalar_mul_parallelized);
    smart_small_scalar_mul_test(param, executor);
}

fn integer_smart_scalar_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_mul_parallelized);
    smart_scalar_mul_test(param, executor);
}

fn integer_smart_scalar_mul_u128_fix_non_reg_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_scalar_mul_parallelized);
    smart_scalar_mul_u128_fix_non_reg_test(param, executor);
}

fn integer_smart_block_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::smart_block_mul_parallelized);
    smart_block_mul_test(param, executor);
}

//=============================================================================
// Default Tests
//=============================================================================

fn integer_default_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::add_parallelized);
    default_add_test(param, executor);
}

fn integer_default_overflowing_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_add_parallelized);
    default_overflowing_add_test(param, executor);
}

fn integer_default_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::sub_parallelized);
    default_sub_test(param, executor);
}

fn integer_default_overflowing_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_sub_parallelized);
    default_overflowing_sub_test(param, executor);
}

// Smaller test for this one
fn integer_default_add_work_efficient<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::add_parallelized_work_efficient);
    default_add_test(param, executor);
}

fn integer_default_sub_work_efficient<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::sub_parallelized_work_efficient);
    default_sub_test(param, executor);
}

fn integer_default_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::mul_parallelized);
    default_mul_test(param, executor);
}

fn integer_default_neg<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::neg_parallelized);
    default_neg_test(param, executor);
}

fn integer_default_bitand<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitand_parallelized);
    default_bitand_test(param, executor);
}

fn integer_default_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitor_parallelized);
    default_bitor_test(param, executor);
}

fn integer_default_bitxor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitxor_parallelized);
    default_bitxor_test(param, executor);
}

fn integer_default_bitnot<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::bitnot_parallelized);
    default_bitnot_test(param, executor);
}

fn integer_default_div_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::div_rem_parallelized);
    default_div_rem_test(param, executor);
}

fn integer_default_div<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::div_parallelized);
    default_div_test(param, executor);
}

fn integer_default_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::rem_parallelized);
    default_rem_test(param, executor);
}

fn integer_default_if_then_else<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::if_then_else_parallelized);
    default_if_then_else_test(param, executor);
}

//=============================================================================
// Default Scalar Tests
//=============================================================================

fn integer_default_scalar_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_add_parallelized);
    default_scalar_add_test(param, executor);
}

fn integer_default_overflowing_scalar_add<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor =
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_scalar_add_parallelized);
    default_overflowing_scalar_add_test(param, executor);
}

fn integer_default_scalar_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_sub_parallelized);
    default_scalar_sub_test(param, executor);
}

fn integer_default_overflowing_scalar_sub<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor =
        CpuFunctionExecutor::new(&ServerKey::unsigned_overflowing_scalar_sub_parallelized);
    default_overflowing_scalar_sub_test(param, executor);
}

fn integer_default_scalar_bitand<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_bitand_parallelized);
    default_scalar_bitand_test(param, executor);
}

fn integer_default_scalar_bitor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_bitor_parallelized);
    default_scalar_bitor_test(param, executor);
}

fn integer_default_scalar_bitxor<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_bitxor_parallelized);
    default_scalar_bitxor_test(param, executor);
}

fn integer_default_small_scalar_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::small_scalar_mul_parallelized);
    default_small_scalar_mul_test(param, executor);
}

fn integer_default_scalar_mul_u128_fix_non_reg_test<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_mul_parallelized);
    default_scalar_mul_u128_fix_non_reg_test(param, executor);
}

fn integer_default_scalar_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_mul_parallelized);
    default_scalar_mul_test(param, executor);
}

fn integer_default_scalar_left_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_left_shift_parallelized);
    default_scalar_left_shift_test(param, executor);
}

fn integer_default_scalar_right_shift<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_right_shift_parallelized);
    default_scalar_right_shift_test(param, executor);
}

fn integer_default_scalar_rotate_right<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_rotate_right_parallelized);
    default_scalar_rotate_right_test(param, executor);
}

fn integer_default_scalar_rotate_left<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_rotate_left_parallelized);
    default_scalar_rotate_left_test(param, executor);
}

fn integer_default_scalar_div_rem<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::scalar_div_rem_parallelized);
    default_scalar_div_rem_test(param, executor);
}

fn integer_default_block_mul<P>(param: P)
where
    P: Into<PBSParameters>,
{
    let executor = CpuFunctionExecutor::new(&ServerKey::block_mul_parallelized);
    default_default_block_mul_test(param, executor);
}

#[test]
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
